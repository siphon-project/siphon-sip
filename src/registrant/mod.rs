//! Outbound Registration (UAC Registrant) — maintains REGISTER bindings
//! to upstream carriers/SBCs.
//!
//! Each [`RegistrantEntry`] represents a single AoR that SIPhon keeps
//! registered at an upstream registrar.  The [`RegistrantManager`] owns
//! all entries and runs a background refresh loop that:
//!
//! - Sends REGISTER at startup for every configured entry.
//! - Re-registers at 50 % of the granted `expires` interval.
//! - Handles 401/407 challenges using [`crate::auth`] digest computation.
//! - Applies exponential backoff on failure.
//! - Sends de-registration (Expires: 0) on shutdown.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::auth::{
    self, DigestChallenge, DigestCredentials, NonceCounter,
};
use crate::hep::HepSender;
use crate::uac::resolve_via_addr;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, StreamConnections, Transport};

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// A registrant state change event emitted by the manager.
#[derive(Debug, Clone)]
pub enum RegistrantEvent {
    /// Registration succeeded (first time or after failure).
    Registered { aor: String },
    /// Re-registration succeeded (was already registered).
    Refreshed { aor: String },
    /// Registration failed (non-auth error or auth exhaustion).
    Failed { aor: String, status_code: u16 },
    /// De-registration sent (shutdown or manual remove).
    Deregistered { aor: String },
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Registration state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrantState {
    /// Not yet attempted.
    Unregistered,
    /// REGISTER sent, waiting for response.
    Registering,
    /// 401/407 received, re-sending with credentials.
    Challenging,
    /// 200 OK received — binding is active.
    Registered,
    /// Last attempt failed (non-401/407 error or auth failure).
    Failed,
}

impl fmt::Display for RegistrantState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unregistered => write!(formatter, "unregistered"),
            Self::Registering => write!(formatter, "registering"),
            Self::Challenging => write!(formatter, "challenging"),
            Self::Registered => write!(formatter, "registered"),
            Self::Failed => write!(formatter, "failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Authentication credentials for a registration entry.
#[derive(Debug, Clone)]
pub struct RegistrantCredentials {
    pub username: String,
    pub password: String,
    /// Optional realm hint — if `None`, derived from the 401 challenge.
    pub realm: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// A single outbound registration binding.
#[derive(Debug)]
pub struct RegistrantEntry {
    /// Address-of-Record (e.g. `sip:alice@carrier.com`).
    pub aor: String,
    /// Registrar URI (e.g. `sip:registrar.carrier.com:5060`).
    pub registrar_uri: String,
    /// Resolved destination for sending REGISTER.
    pub destination: SocketAddr,
    /// Original hostname:port for DNS re-resolution on failure.
    pub address_str: Option<String>,
    /// Transport to use (default: UDP).
    pub transport: Transport,
    /// Authentication credentials.
    pub credentials: RegistrantCredentials,
    /// Desired registration interval (seconds).
    pub interval_secs: u32,
    /// Contact URI to bind (auto-generated if not specified).
    pub contact_uri: Option<String>,

    // --- Runtime state ---
    pub state: RegistrantState,
    /// When the current registration expires.
    pub expires_at: Option<Instant>,
    /// When to next attempt registration.
    pub next_attempt: Instant,
    /// Current backoff duration for retries after failure.
    pub backoff: Duration,
    /// Per-entry CSeq counter.
    pub cseq: AtomicU32,
    /// Nonce counter for digest auth.
    pub nonce_counter: NonceCounter,
    /// Call-ID for this registration dialog (stable across refreshes).
    pub call_id: String,
    /// Number of consecutive failures.
    pub failure_count: u32,
    /// When the last REGISTER was sent (for transaction timeout detection).
    pub last_sent_at: Option<Instant>,
}

impl RegistrantEntry {
    pub fn new(
        aor: String,
        registrar_uri: String,
        destination: SocketAddr,
        transport: Transport,
        credentials: RegistrantCredentials,
        interval_secs: u32,
        contact_uri: Option<String>,
    ) -> Self {
        Self {
            aor,
            registrar_uri,
            destination,
            address_str: None,
            transport,
            credentials,
            interval_secs,
            contact_uri,
            state: RegistrantState::Unregistered,
            expires_at: None,
            next_attempt: Instant::now(),
            backoff: Duration::from_secs(5),
            cseq: AtomicU32::new(1),
            nonce_counter: NonceCounter::new(),
            call_id: format!("reg-{}", uuid::Uuid::new_v4()),
            failure_count: 0,
            last_sent_at: None,
        }
    }

    /// Returns seconds until expiry, or 0 if expired/not registered.
    pub fn expires_in(&self) -> u64 {
        self.expires_at
            .map(|at| {
                at.checked_duration_since(Instant::now())
                    .map(|duration| duration.as_secs())
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    /// Next CSeq value.
    pub fn next_cseq(&self) -> u32 {
        self.cseq.fetch_add(1, Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Manager
// ---------------------------------------------------------------------------

/// Manages all outbound registrations.
pub struct RegistrantManager {
    entries: DashMap<String, RegistrantEntry>,
    /// Default interval when not specified per-entry.
    pub default_interval: u32,
    /// Base retry interval on failure.
    pub retry_interval: Duration,
    /// Maximum retry interval (backoff cap).
    pub max_retry_interval: Duration,
    /// User-Agent header value for outbound REGISTERs.
    user_agent_header: Option<String>,
    /// Broadcast channel for registrant state change events.
    event_sender: broadcast::Sender<RegistrantEvent>,
}

impl RegistrantManager {
    pub fn new(
        default_interval: u32,
        retry_interval: Duration,
        max_retry_interval: Duration,
        user_agent_header: Option<String>,
    ) -> Self {
        let (event_sender, _) = broadcast::channel(64);
        Self {
            entries: DashMap::new(),
            default_interval,
            retry_interval,
            max_retry_interval,
            user_agent_header,
            event_sender,
        }
    }

    /// Subscribe to registrant state change events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<RegistrantEvent> {
        self.event_sender.subscribe()
    }

    /// Emit a registrant event (best-effort, ignores if no receivers).
    fn emit_event(&self, event: RegistrantEvent) {
        let _ = self.event_sender.send(event);
    }

    /// Add a new registration entry.
    pub fn add(&self, entry: RegistrantEntry) {
        info!(aor = %entry.aor, registrar = %entry.registrar_uri, "registrant added");
        self.entries.insert(entry.aor.clone(), entry);
    }

    /// Remove a registration entry by AoR.
    pub fn remove(&self, aor: &str) -> Option<RegistrantEntry> {
        let removed = self.entries.remove(aor).map(|(_, entry)| entry);
        if removed.is_some() {
            self.emit_event(RegistrantEvent::Deregistered { aor: aor.to_string() });
        }
        removed
    }

    /// Get number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get the state of an entry.
    pub fn state(&self, aor: &str) -> Option<RegistrantState> {
        self.entries.get(aor).map(|entry| entry.state)
    }

    /// List all AoRs and their states.
    pub fn list(&self) -> Vec<(String, RegistrantState, u64)> {
        self.entries
            .iter()
            .map(|entry| {
                (
                    entry.aor.clone(),
                    entry.state,
                    entry.expires_in(),
                )
            })
            .collect()
    }

    /// Get extended info for a single entry (used by dispatcher for event callbacks).
    ///
    /// Returns `(expires_in, failure_count, registrar_uri)`.
    pub fn entry_info(&self, aor: &str) -> Option<(u64, u32, String)> {
        self.entries.get(aor).map(|entry| {
            (entry.expires_in(), entry.failure_count, entry.registrar_uri.clone())
        })
    }

    /// Force an immediate refresh for a specific AoR.
    pub fn refresh(&self, aor: &str) -> bool {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            entry.next_attempt = Instant::now();
            entry.state = RegistrantState::Unregistered;
            true
        } else {
            false
        }
    }

    /// Build a REGISTER request for an entry.
    ///
    /// `listen_addrs` maps each transport to its listen address. The entry's
    /// transport is used to pick the correct local address (and port) for the
    /// Contact and Via headers. Falls back to `local_addr` when no
    /// transport-specific address is configured.
    pub fn build_register(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        expires: u32,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;
        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri: SipUri = SipUri::new(
            entry
                .registrar_uri
                .strip_prefix("sip:")
                .unwrap_or(&entry.registrar_uri)
                .to_string(),
        );

        let contact = entry
            .contact_uri
            .clone()
            .unwrap_or_else(|| default_contact_uri(&entry.credentials.username, effective_addr, entry.transport));

        let via = format!(
            "SIP/2.0/{} {};branch={}",
            entry.transport, effective_addr, branch
        );

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!(
                "<{}>;tag=reg-{}",
                entry.aor, cseq
            ))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header("Contact", format!("<{}>", contact))
            .header("Expires", expires.to_string())
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        if expires > 0 {
            entry.state = RegistrantState::Registering;
            entry.last_sent_at = Some(Instant::now());
        }

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build REGISTER");
                None
            }
        }
    }

    /// Build an authenticated REGISTER retry after receiving a 401/407 challenge.
    pub fn build_register_with_auth(
        &self,
        aor: &str,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
        challenge: &DigestChallenge,
        is_proxy_auth: bool,
        expires: u32,
    ) -> Option<(SipMessage, String, SocketAddr, Transport)> {
        let mut entry = self.entries.get_mut(aor)?;
        let effective_addr = listen_addrs
            .get(&entry.transport)
            .copied()
            .unwrap_or(local_addr);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());

        let request_uri_str = entry
            .registrar_uri
            .strip_prefix("sip:")
            .unwrap_or(&entry.registrar_uri)
            .to_string();
        let request_uri = SipUri::new(request_uri_str.clone());

        let contact = entry
            .contact_uri
            .clone()
            .unwrap_or_else(|| default_contact_uri(&entry.credentials.username, effective_addr, entry.transport));

        let via = format!(
            "SIP/2.0/{} {};branch={}",
            entry.transport, effective_addr, branch
        );

        let nc = entry.nonce_counter.next_for(&challenge.nonce);
        let cnonce = format!("{:08x}", rand_u32());

        let digest_uri = format!("sip:{request_uri_str}");
        let credentials = DigestCredentials {
            username: entry.credentials.username.clone(),
            password: entry.credentials.password.clone(),
        };

        let auth_header_value = auth::format_authorization_header(
            challenge,
            &credentials,
            "REGISTER",
            &digest_uri,
            Some(nc),
            Some(&cnonce),
        );

        let auth_header_name = if is_proxy_auth {
            "Proxy-Authorization"
        } else {
            "Authorization"
        };

        entry.state = RegistrantState::Challenging;
        entry.last_sent_at = Some(Instant::now());

        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, request_uri)
            .via(via)
            .to(format!("<{}>", entry.aor))
            .from(format!(
                "<{}>;tag=reg-{}",
                entry.aor, cseq
            ))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header("Contact", format!("<{}>", contact))
            .header("Expires", expires.to_string())
            .header(auth_header_name, auth_header_value)
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        let message = builder.build();

        let destination = entry.destination;
        let transport = entry.transport;

        match message {
            Ok(message) => Some((message, branch, destination, transport)),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build authenticated REGISTER");
                None
            }
        }
    }

    /// Handle a successful 200 OK response.
    pub fn handle_success(&self, aor: &str, granted_expires: u32) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            let was_registered = entry.state == RegistrantState::Registered;
            let refresh_at = Duration::from_secs((granted_expires as u64) / 2);
            entry.state = RegistrantState::Registered;
            entry.expires_at = Some(Instant::now() + Duration::from_secs(granted_expires as u64));
            entry.next_attempt = Instant::now() + refresh_at;
            entry.failure_count = 0;
            entry.backoff = Duration::from_secs(5);
            entry.last_sent_at = None;
            info!(
                aor = %entry.aor,
                expires = granted_expires,
                refresh_in = ?refresh_at,
                "registered successfully"
            );
            let aor_owned = entry.aor.clone();
            drop(entry);
            if was_registered {
                self.emit_event(RegistrantEvent::Refreshed { aor: aor_owned });
            } else {
                self.emit_event(RegistrantEvent::Registered { aor: aor_owned });
            }
        }
    }

    /// Handle a failure response (non-401/407, or auth failed twice).
    pub fn handle_failure(&self, aor: &str, status_code: u16) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            entry.state = RegistrantState::Failed;
            entry.failure_count += 1;
            entry.expires_at = None;

            // Exponential backoff capped at max_retry_interval
            let backoff = std::cmp::min(
                entry.backoff * 2,
                self.max_retry_interval,
            );
            entry.backoff = backoff;
            entry.next_attempt = Instant::now() + backoff;

            warn!(
                aor = %entry.aor,
                status_code,
                failures = entry.failure_count,
                retry_in = ?backoff,
                "registration failed"
            );

            // Re-resolve DNS to try a different IP on next attempt
            if let Some(ref address_str) = entry.address_str {
                use std::net::ToSocketAddrs;
                if let Ok(mut addrs) = address_str.to_socket_addrs() {
                    let old = entry.destination;
                    let new_addr = addrs.find(|a| *a != old)
                        .or_else(|| address_str.to_socket_addrs().ok()?.next());
                    if let Some(new_addr) = new_addr {
                        if new_addr != old {
                            info!(
                                aor = %entry.aor,
                                old = %old,
                                new = %new_addr,
                                "re-resolved registrar to different IP"
                            );
                            entry.destination = new_addr;
                        }
                    }
                }
            }

            let aor_owned = entry.aor.clone();
            drop(entry);
            self.emit_event(RegistrantEvent::Failed { aor: aor_owned, status_code });
        }
    }

    /// Get entries that are due for registration attempt.
    pub fn entries_due(&self) -> Vec<String> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|entry| entry.next_attempt <= now)
            .filter(|entry| matches!(
                entry.state,
                RegistrantState::Unregistered
                    | RegistrantState::Registered
                    | RegistrantState::Failed
            ))
            .map(|entry| entry.aor.clone())
            .collect()
    }

    /// RFC 3261 Timer F — non-INVITE transaction timeout (32 seconds).
    const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(32);

    /// Find entries stuck in `Registering` or `Challenging` past the
    /// transaction timeout (RFC 3261 Timer F, 32s).  The registration
    /// loop should treat these as transport-level failures.
    pub fn entries_timed_out(&self) -> Vec<String> {
        let now = Instant::now();
        self.entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.state,
                    RegistrantState::Registering | RegistrantState::Challenging
                ) && entry
                    .last_sent_at
                    .map(|sent| now.duration_since(sent) > Self::TRANSACTION_TIMEOUT)
                    .unwrap_or(false)
            })
            .map(|entry| entry.aor.clone())
            .collect()
    }

    /// Build de-registration (Expires: 0) for all active entries.
    pub fn build_deregistrations(
        &self,
        local_addr: SocketAddr,
        listen_addrs: &HashMap<Transport, SocketAddr>,
    ) -> Vec<(SipMessage, SocketAddr, Transport)> {
        // Collect AoRs first to avoid deadlock: iter() holds a read lock on
        // each DashMap shard, and build_register() needs a write lock (get_mut).
        let registered_aors: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.state == RegistrantState::Registered)
            .map(|entry| entry.aor.clone())
            .collect();

        let mut result = Vec::new();
        for aor in &registered_aors {
            if let Some((message, _branch, destination, transport)) =
                self.build_register(aor, local_addr, listen_addrs, 0)
            {
                result.push((message, destination, transport));
            }
        }
        result
    }

    /// Match an incoming response to a registrant entry by branch prefix.
    ///
    /// Returns the AoR if matched, plus the status code for processing.
    pub fn match_response(&self, branch: &str) -> Option<String> {
        if !branch.starts_with("z9hG4bK-reg-") {
            return None;
        }
        // Find entry by matching call_id in the response — but since we
        // can't easily do that here, we search all entries whose state is
        // Registering or Challenging.
        for entry in self.entries.iter() {
            if matches!(
                entry.state,
                RegistrantState::Registering | RegistrantState::Challenging
            ) {
                return Some(entry.aor.clone());
            }
        }
        None
    }

    /// More precise matching: find entry by Call-ID.
    pub fn find_by_call_id(&self, call_id: &str) -> Option<String> {
        self.entries
            .iter()
            .find(|entry| entry.call_id == call_id)
            .map(|entry| entry.aor.clone())
    }
}

impl fmt::Debug for RegistrantManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrantManager")
            .field("entries", &self.entries.len())
            .field("default_interval", &self.default_interval)
            .finish()
    }
}

/// Background registration refresh loop.
///
/// Runs until the provided shutdown signal fires. On shutdown, sends
/// de-registration (Expires: 0) for all active bindings.
pub async fn registration_loop(
    manager: Arc<RegistrantManager>,
    outbound: Arc<OutboundRouter>,
    local_addr: SocketAddr,
    listen_addrs: HashMap<Transport, SocketAddr>,
    advertised_addrs: HashMap<Transport, String>,
    advertised_address: Option<String>,
    hep_sender: Option<Arc<HepSender>>,
    stream_connections: Option<StreamConnections>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let tick_interval = Duration::from_secs(5);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(tick_interval) => {
                // Detect connection loss on connection-oriented transports
                // (TLS/TCP/SCTP).  The pool removes dead connections from the
                // stream registry; if the registrar destination is gone, force
                // an immediate re-register instead of waiting for the
                // refresh timer.  The lookup is transport-filtered so an
                // unrelated WS/WSS UE sharing the trunk's IP can't mask a dead
                // trunk connection (preserves the pre-unification TLS-only
                // membership semantics exactly).
                if let Some(ref stream_connections) = stream_connections {
                    let stale: Vec<String> = manager.entries.iter()
                        .filter(|entry| {
                            entry.state == RegistrantState::Registered
                                && matches!(entry.transport, Transport::Tls | Transport::Tcp | Transport::Sctp)
                                && !stream_connections.has_ip_transport(entry.destination.ip(), entry.transport)
                        })
                        .map(|entry| entry.aor.clone())
                        .collect();
                    for aor in stale {
                        warn!(aor = %aor, "connection lost — forcing immediate re-register");
                        manager.refresh(&aor);
                    }
                }

                // Time out entries stuck in Registering/Challenging (RFC 3261
                // Timer F — 32s).  Catches dead sockets where no response
                // ever arrives.
                let timed_out = manager.entries_timed_out();
                for aor in &timed_out {
                    warn!(aor = %aor, "REGISTER transaction timed out — no response received");
                    manager.handle_failure(aor, 0);
                }

                let due = manager.entries_due();
                for aor in due {
                    if let Some((message, branch, destination, transport)) =
                        manager.build_register(&aor, local_addr, &listen_addrs, manager.default_interval)
                    {
                        let data = Bytes::from(message.to_bytes());

                        // HEP capture — outbound REGISTER
                        if let Some(ref hep) = hep_sender {
                            let via_addr = resolve_via_addr(local_addr, &transport, &advertised_addrs, advertised_address.as_deref());
                            hep.capture_outbound(via_addr, destination, transport, &data);
                        }

                        let outbound_message = OutboundMessage {
                            connection_id: ConnectionId::default(),
                            transport,
                            destination,
                            data,
                            source_local_addr: None,
                        };
                        debug!(aor = %aor, branch = %branch, "sending REGISTER");
                        if let Err(error) = outbound.send(outbound_message) {
                            warn!(aor = %aor, %error, "failed to send REGISTER");
                            manager.handle_failure(&aor, 0);
                        }
                    }
                }
            }
            result = shutdown.changed() => {
                if result.is_ok() && *shutdown.borrow() {
                    info!("registrant shutting down — de-registering all bindings");
                    let dereg_messages = manager.build_deregistrations(local_addr, &listen_addrs);
                    for (message, destination, transport) in dereg_messages {
                        let data = Bytes::from(message.to_bytes());

                        // HEP capture — outbound de-registration
                        if let Some(ref hep) = hep_sender {
                            let via_addr = resolve_via_addr(local_addr, &transport, &advertised_addrs, advertised_address.as_deref());
                            hep.capture_outbound(via_addr, destination, transport, &data);
                        }

                        let outbound_message = OutboundMessage {
                            connection_id: ConnectionId::default(),
                            transport,
                            destination,
                            data,
                            source_local_addr: None,
                        };
                        let _ = outbound.send(outbound_message);
                    }
                    break;
                }
            }
        }
    }
}

/// Build a default Contact URI from the entry's username, effective address, and transport.
///
/// Appends `;transport=<proto>` for non-UDP transports (UDP is the default per RFC 3261).
fn default_contact_uri(username: &str, address: SocketAddr, transport: Transport) -> String {
    let transport_param = match transport {
        Transport::Udp => "",
        Transport::Tcp => ";transport=tcp",
        Transport::Tls => ";transport=tls",
        Transport::WebSocket => ";transport=ws",
        Transport::WebSocketSecure => ";transport=wss",
        Transport::Sctp => ";transport=sctp",
    };
    format!("sip:{}@{}{}", username, address, transport_param)
}

/// Simple PRNG for cnonce generation — not cryptographic, just unique enough.
fn rand_u32() -> u32 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64);
    hasher.finish() as u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_manager() -> RegistrantManager {
        RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            Some("SIPhon/test".to_string()),
        )
    }

    fn make_entry(aor: &str) -> RegistrantEntry {
        RegistrantEntry::new(
            aor.to_string(),
            "sip:registrar.carrier.com:5060".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            RegistrantCredentials {
                username: "alice".to_string(),
                password: "secret123".to_string(),
                realm: None,
            },
            3600,
            None,
        )
    }

    #[test]
    fn add_and_list() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.add(make_entry("sip:bob@carrier.com"));

        assert_eq!(manager.len(), 2);
        let list = manager.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn remove_entry() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        assert_eq!(manager.len(), 1);

        let removed = manager.remove("sip:alice@carrier.com");
        assert!(removed.is_some());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let manager = make_manager();
        assert!(manager.remove("sip:nobody@example.com").is_none());
    }

    #[test]
    fn initial_state_is_unregistered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Unregistered)
        );
    }

    #[test]
    fn entries_due_includes_new_entries() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let due = manager.entries_due();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], "sip:alice@carrier.com");
    }

    #[test]
    fn build_register_sets_registering() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let result = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        assert!(result.is_some());

        let (message, branch, destination, transport) = result.unwrap();
        assert!(branch.starts_with("z9hG4bK-reg-"));
        assert_eq!(destination, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(transport, Transport::Udp);

        // Check the message has correct headers
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("REGISTER"));
        assert!(raw.contains("sip:alice@carrier.com"));
        assert!(raw.contains("Expires: 3600"));
        assert!(raw.contains("Contact:"));

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Registering)
        );
    }

    #[test]
    fn build_register_tls_uses_correct_port_and_transport() {
        let manager = make_manager();
        let mut entry = make_entry("sip:trunk@carrier.com");
        entry.transport = Transport::Tls;
        entry.destination = "10.0.0.1:5061".parse().unwrap();
        manager.add(entry);

        let mut listen = HashMap::new();
        listen.insert(Transport::Tls, "172.16.0.153:5061".parse().unwrap());

        let result = manager.build_register(
            "sip:trunk@carrier.com",
            "172.16.0.153:5060".parse().unwrap(),
            &listen,
            3600,
        );
        assert!(result.is_some());

        let (message, _, _, transport) = result.unwrap();
        assert_eq!(transport, Transport::Tls);

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        // Contact should use TLS listen port and transport param
        assert!(
            raw.contains("172.16.0.153:5061;transport=tls"),
            "Contact should use TLS port 5061 and transport=tls: {raw}"
        );
        // Via should also use TLS port
        assert!(
            raw.contains("SIP/2.0/TLS 172.16.0.153:5061"),
            "Via should use TLS port 5061: {raw}"
        );
    }

    #[test]
    fn handle_success_transitions_to_registered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Simulate registration attempt
        let _ = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        manager.handle_success("sip:alice@carrier.com", 3600);

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Registered)
        );

        // Should not be due immediately — refresh at 50% of expires
        let due = manager.entries_due();
        assert!(due.is_empty());
    }

    #[test]
    fn handle_failure_transitions_to_failed_with_backoff() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.handle_failure("sip:alice@carrier.com", 403);

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Failed)
        );

        // Should not be due immediately due to backoff
        let due = manager.entries_due();
        assert!(due.is_empty());
    }

    #[test]
    fn backoff_increases_on_repeated_failures() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // First failure
        manager.handle_failure("sip:alice@carrier.com", 503);
        let backoff_1 = manager
            .entries
            .get("sip:alice@carrier.com")
            .unwrap()
            .backoff;

        // Override next_attempt to make it due again
        manager
            .entries
            .get_mut("sip:alice@carrier.com")
            .unwrap()
            .next_attempt = Instant::now();

        // Second failure
        manager.handle_failure("sip:alice@carrier.com", 503);
        let backoff_2 = manager
            .entries
            .get("sip:alice@carrier.com")
            .unwrap()
            .backoff;

        assert!(backoff_2 > backoff_1);
    }

    #[test]
    fn backoff_capped_at_max() {
        let manager = RegistrantManager::new(
            3600,
            Duration::from_secs(10),
            Duration::from_secs(30),
            None,
        );
        manager.add(make_entry("sip:alice@carrier.com"));

        // Fail many times
        for _ in 0..20 {
            manager.handle_failure("sip:alice@carrier.com", 503);
        }

        let backoff = manager
            .entries
            .get("sip:alice@carrier.com")
            .unwrap()
            .backoff;
        assert!(backoff <= Duration::from_secs(30));
    }

    #[test]
    fn success_resets_backoff_and_failure_count() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Fail a few times
        manager.handle_failure("sip:alice@carrier.com", 503);
        manager.handle_failure("sip:alice@carrier.com", 503);

        // Then succeed
        manager.handle_success("sip:alice@carrier.com", 3600);

        let entry = manager.entries.get("sip:alice@carrier.com").unwrap();
        assert_eq!(entry.failure_count, 0);
        assert_eq!(entry.backoff, Duration::from_secs(5));
    }

    #[test]
    fn refresh_resets_state_and_schedule() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.handle_success("sip:alice@carrier.com", 3600);

        // Not due yet
        assert!(manager.entries_due().is_empty());

        // Force refresh
        assert!(manager.refresh("sip:alice@carrier.com"));

        // Now it should be due
        let due = manager.entries_due();
        assert_eq!(due.len(), 1);
    }

    #[test]
    fn refresh_nonexistent_returns_false() {
        let manager = make_manager();
        assert!(!manager.refresh("sip:nobody@example.com"));
    }

    #[test]
    fn find_by_call_id() {
        let manager = make_manager();
        let entry = make_entry("sip:alice@carrier.com");
        let call_id = entry.call_id.clone();
        manager.add(entry);

        assert_eq!(
            manager.find_by_call_id(&call_id),
            Some("sip:alice@carrier.com".to_string())
        );
        assert!(manager.find_by_call_id("nonexistent-call-id").is_none());
    }

    #[test]
    fn expires_in_when_not_registered() {
        let entry = make_entry("sip:alice@carrier.com");
        assert_eq!(entry.expires_in(), 0);
    }

    #[test]
    fn cseq_increments() {
        let entry = make_entry("sip:alice@carrier.com");
        let first = entry.next_cseq();
        let second = entry.next_cseq();
        assert_eq!(second, first + 1);
    }

    #[test]
    fn state_display() {
        assert_eq!(RegistrantState::Unregistered.to_string(), "unregistered");
        assert_eq!(RegistrantState::Registering.to_string(), "registering");
        assert_eq!(RegistrantState::Challenging.to_string(), "challenging");
        assert_eq!(RegistrantState::Registered.to_string(), "registered");
        assert_eq!(RegistrantState::Failed.to_string(), "failed");
    }

    #[test]
    fn build_register_with_auth_sets_challenging() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let challenge = DigestChallenge {
            realm: "carrier.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: auth::DigestAlgorithm::Md5,
            stale: false,
        };

        let result = manager.build_register_with_auth(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            &challenge,
            false,
            3600,
        );
        assert!(result.is_some());

        let (message, branch, _, _) = result.unwrap();
        assert!(branch.starts_with("z9hG4bK-reg-"));

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("Authorization:"));
        assert!(raw.contains("username=\"alice\""));
        assert!(raw.contains("realm=\"carrier.com\""));

        assert_eq!(
            manager.state("sip:alice@carrier.com"),
            Some(RegistrantState::Challenging)
        );
    }

    #[test]
    fn build_deregistrations_only_for_registered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.add(make_entry("sip:bob@carrier.com"));

        // Register only alice
        manager.handle_success("sip:alice@carrier.com", 3600);

        let dereg = manager.build_deregistrations("127.0.0.1:5060".parse().unwrap(), &HashMap::new());
        assert_eq!(dereg.len(), 1);

        let bytes = dereg[0].0.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("Expires: 0"));
    }

    #[test]
    fn concurrent_access() {
        let manager = Arc::new(make_manager());
        let mut handles = Vec::new();

        for index in 0..10 {
            let manager = Arc::clone(&manager);
            handles.push(std::thread::spawn(move || {
                let aor = format!("sip:user{}@carrier.com", index);
                manager.add(make_entry(&aor));
                manager.state(&aor);
                manager.list();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(manager.len(), 10);
    }

    #[test]
    fn is_empty_on_new_manager() {
        let manager = make_manager();
        assert!(manager.is_empty());
        manager.add(make_entry("sip:alice@carrier.com"));
        assert!(!manager.is_empty());
    }

    #[test]
    fn manager_debug() {
        let manager = make_manager();
        let debug = format!("{:?}", manager);
        assert!(debug.contains("RegistrantManager"));
        assert!(debug.contains("entries"));
    }

    #[test]
    fn event_emitted_on_first_registration() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.handle_success("sip:alice@carrier.com", 3600);

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Registered { ref aor } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn event_emitted_on_refresh() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.handle_success("sip:alice@carrier.com", 3600);

        let mut receiver = manager.subscribe_events();
        // Second success while already Registered → Refreshed
        manager.handle_success("sip:alice@carrier.com", 3600);

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Refreshed { ref aor } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn event_emitted_on_failure() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.handle_failure("sip:alice@carrier.com", 503);

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Failed { ref aor, status_code: 503 } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn event_emitted_on_remove() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.remove("sip:alice@carrier.com");

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrantEvent::Deregistered { ref aor } if aor == "sip:alice@carrier.com"));
    }

    #[test]
    fn no_event_on_remove_nonexistent() {
        let manager = make_manager();
        let mut receiver = manager.subscribe_events();

        manager.remove("sip:nobody@carrier.com");

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn entry_info_returns_data() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));
        manager.handle_success("sip:alice@carrier.com", 3600);

        let (expires_in, failure_count, registrar) = manager.entry_info("sip:alice@carrier.com").unwrap();
        assert!(expires_in > 0);
        assert_eq!(failure_count, 0);
        assert_eq!(registrar, "sip:registrar.carrier.com:5060");
    }

    #[test]
    fn entry_info_none_for_missing() {
        let manager = make_manager();
        assert!(manager.entry_info("sip:nobody@carrier.com").is_none());
    }

    #[test]
    fn build_register_sets_last_sent_at() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Before building: no last_sent_at
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_none());

        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        // After building: last_sent_at should be set
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_some());
    }

    #[test]
    fn success_clears_last_sent_at() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_some());

        manager.handle_success("sip:alice@carrier.com", 3600);
        assert!(manager.entries.get("sip:alice@carrier.com").unwrap().last_sent_at.is_none());
    }

    #[test]
    fn entries_timed_out_not_triggered_before_timeout() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Send a REGISTER (sets state to Registering + last_sent_at)
        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        // Should not be timed out yet (just sent)
        assert!(manager.entries_timed_out().is_empty());
    }

    #[test]
    fn entries_timed_out_triggered_after_timeout() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );

        // Simulate passage of time by backdating last_sent_at
        manager.entries.get_mut("sip:alice@carrier.com").unwrap().last_sent_at =
            Some(Instant::now() - Duration::from_secs(33));

        let timed_out = manager.entries_timed_out();
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0], "sip:alice@carrier.com");
    }

    #[test]
    fn build_register_includes_user_agent() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let result = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        let (message, _, _, _) = result.unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            raw.contains("User-Agent: SIPhon/test"),
            "REGISTER should include User-Agent header: {raw}"
        );
    }

    #[test]
    fn build_register_omits_user_agent_when_none() {
        let manager = RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            None,
        );
        manager.add(make_entry("sip:alice@carrier.com"));

        let result = manager.build_register(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            3600,
        );
        let (message, _, _, _) = result.unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            !raw.contains("User-Agent:"),
            "REGISTER should not include User-Agent header when None: {raw}"
        );
    }

    #[test]
    fn build_register_with_auth_includes_user_agent() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        let challenge = DigestChallenge {
            realm: "carrier.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: auth::DigestAlgorithm::Md5,
            stale: false,
        };

        let result = manager.build_register_with_auth(
            "sip:alice@carrier.com",
            "127.0.0.1:5060".parse().unwrap(),
            &HashMap::new(),
            &challenge,
            false,
            3600,
        );
        let (message, _, _, _) = result.unwrap();
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(
            raw.contains("User-Agent: SIPhon/test"),
            "Authenticated REGISTER should include User-Agent header: {raw}"
        );
    }

    #[test]
    fn entries_timed_out_not_triggered_for_registered() {
        let manager = make_manager();
        manager.add(make_entry("sip:alice@carrier.com"));

        // Registered entries should never time out (even with stale last_sent_at)
        manager.handle_success("sip:alice@carrier.com", 3600);
        manager.entries.get_mut("sip:alice@carrier.com").unwrap().last_sent_at =
            Some(Instant::now() - Duration::from_secs(60));

        assert!(manager.entries_timed_out().is_empty());
    }
}
