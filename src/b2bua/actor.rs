//! B2BUA actor model — per-leg state ownership with intercommunication.
//!
//! ## Architecture
//!
//! - **[`Leg`]**: Pure state for a single SIP dialog leg. Each leg owns its
//!   [`Dialog`] (Call-ID, tags, CSeq) and [`TransportInfo`] independently.
//!
//! - **[`CallActor`]**: Per-call supervisor. Holds A-leg + B-leg(s), coordinates
//!   forking, winner selection, and call teardown.
//!
//! - **[`LegRegistry`]**: Global routing table mapping SIP identifiers
//!   (Call-ID, Via branch) → internal call ID, so the dispatcher can route
//!   inbound SIP messages to the correct call.
//!
//! - **[`LegActor`]**: Async actor wrapping a `Leg` + channels.
//!   Classifies inbound SIP messages into [`CallEvent`]s for the dispatcher.
//!
//! ## Forking
//!
//! A `CallActor` can hold multiple B-legs. Each B-leg has independent dialog
//! state. The call actor tracks per-leg status and coordinates winner selection.
//!
//! ## Design
//!
//! - Each leg **owns** its dialog state via [`Dialog`].
//! - Legs are independent entities with separate transport bindings.
//! - `LegRegistry` provides SIP-level routing (Call-ID, branch → internal ID).
//! - Foundation for API-driven calls: create a `Leg` without an inbound INVITE.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use tracing::debug;

use crate::sip::message::SipMessage;
use crate::transport::{ConnectionId, Transport};

// ---------------------------------------------------------------------------
// Session timer (RFC 4028)
// ---------------------------------------------------------------------------

/// Tracks the negotiated session timer state for a call (RFC 4028).
#[derive(Debug, Clone)]
pub struct SessionTimerState {
    /// Negotiated Session-Expires value in seconds.
    pub session_expires: u32,
    /// Who is refreshing: "uac" or "uas" (RFC 4028).
    pub refresher: String,
    /// When the timer was last reset (on 200 OK or successful refresh).
    pub last_refresh: std::time::Instant,
}

// ---------------------------------------------------------------------------
// Leg identity
// ---------------------------------------------------------------------------

/// Which side of the B2BUA this leg represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegSide {
    /// Inbound leg (caller → SIPhon).
    A,
    /// Outbound leg (SIPhon → callee).
    B,
}

/// Unique identifier for a leg.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LegId(pub String);

impl Default for LegId {
    fn default() -> Self {
        Self::new()
    }
}

impl LegId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for LegId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Dialog state (owned by each leg)
// ---------------------------------------------------------------------------

/// SIP dialog state owned by a single leg.
///
/// Each leg has its own Call-ID, tags, CSeq counters, and target URI.
#[derive(Debug, Clone)]
pub struct Dialog {
    /// SIP Call-ID for this leg's dialog.
    pub call_id: String,
    /// Our local tag (From-tag for UAC/outbound, To-tag for UAS/inbound).
    pub local_tag: String,
    /// Remote party's tag (learned from responses/requests).
    pub remote_tag: Option<String>,
    /// Local CSeq counter (incremented for each request we originate).
    pub local_cseq: u32,
    /// Last CSeq received from the remote side.
    pub remote_cseq: Option<u32>,
    /// Target URI for this leg (Request-URI for outbound INVITEs).
    pub target_uri: Option<String>,
    /// Contact URI we advertised to the remote side for this leg.
    pub local_contact: Option<String>,
    /// Contact URI the remote side advertised (from INVITE Contact or 200 OK Contact).
    pub remote_contact: Option<String>,
    /// Remote party's AoR (Address of Record) — the To URI host from the
    /// initial INVITE. Used in in-dialog To headers (not the Contact/RURI
    /// which changes per RFC 3261 §12.2.1.1).
    pub remote_aor_host: Option<String>,
    /// Dialog route set (RFC 3261 §12.1.2): Record-Route from the dialog-
    /// creating transaction, reversed for the UAC side. Used as Route
    /// headers in subsequent in-dialog requests (BYE, re-INVITE, etc.).
    pub route_set: Vec<String>,
    /// Our From URI for this dialog (for mid-dialog requests like BYE).
    /// Must match the From used in the dialog-creating request.
    pub local_from_uri: Option<String>,
    /// Remote To URI for this dialog (for mid-dialog requests like BYE).
    pub remote_to_uri: Option<String>,
}

impl Dialog {
    /// Create a new outbound dialog (B-leg / UAC side).
    pub fn new_outbound(call_id: String, local_tag: String, target_uri: String) -> Self {
        Self {
            call_id,
            local_tag,
            remote_tag: None,
            local_cseq: 1,
            remote_cseq: None,
            target_uri: Some(target_uri),
            local_contact: None,
            remote_contact: None,
            remote_aor_host: None,
            route_set: vec![],
            local_from_uri: None,
            remote_to_uri: None,
        }
    }

    /// Create a dialog from an inbound INVITE (A-leg / UAS side).
    pub fn from_inbound(call_id: String, remote_tag: String) -> Self {
        let local_tag = generate_tag();
        Self {
            call_id,
            local_tag,
            remote_tag: Some(remote_tag),
            local_cseq: 1,
            remote_cseq: None,
            target_uri: None,
            local_contact: None,
            remote_contact: None,
            remote_aor_host: None,
            route_set: vec![],
            local_from_uri: None,
            remote_to_uri: None,
        }
    }

    /// Rewrite dialog headers (Call-ID + From-tag, optionally To-tag) on a SIP message.
    ///
    /// - Replaces `Call-ID` with `new_call_id`.
    /// - Swaps `old_from_tag` → `new_from_tag` in the From header (string match
    ///   on `;tag=…`). Same swap is applied to the To header — load-bearing for
    ///   the rare case where From-tag and To-tag happen to coincide, otherwise
    ///   a no-op there.
    /// - When `new_to_tag` is `Some(tag)` AND the inbound message already
    ///   carries a To-tag, the To-tag is replaced with `tag` (RFC 3261
    ///   §12.2.1.1 — across a B2BUA dialog boundary, the receiving UA matches
    ///   on the dialog tags *we* assigned to its leg, not the far end's).
    ///   `Some("")` clears the tag; `None` leaves the To header untouched
    ///   (caller's responsibility for tagless messages — out-of-dialog
    ///   requests, 100 Trying without an early dialog, …).
    pub fn rewrite_headers(
        message: &mut SipMessage,
        new_call_id: &str,
        old_from_tag: &str,
        new_from_tag: &str,
        new_to_tag: Option<&str>,
    ) {
        message.headers.set("Call-ID", new_call_id.to_string());

        let old_pattern = format!("tag={}", old_from_tag);
        let new_pattern = format!("tag={}", new_from_tag);

        if let Some(from) = message.headers.get("From").or_else(|| message.headers.get("f")) {
            if from.contains(&old_pattern) {
                let new_from = from.replace(&old_pattern, &new_pattern);
                message.headers.set("From", new_from);
            }
        }
        if let Some(to) = message.headers.get("To").or_else(|| message.headers.get("t")) {
            if to.contains(&old_pattern) {
                let new_to = to.replace(&old_pattern, &new_pattern);
                message.headers.set("To", new_to);
            }
        }

        if let Some(new_tag) = new_to_tag {
            if let Some(to) = message.headers.get("To").or_else(|| message.headers.get("t")) {
                if let Ok(mut name_addr) = crate::sip::headers::nameaddr::NameAddr::parse(to) {
                    if name_addr.tag.is_some() {
                        name_addr.tag = if new_tag.is_empty() {
                            None
                        } else {
                            Some(new_tag.to_string())
                        };
                        message.headers.set("To", name_addr.to_string());
                    }
                }
            }
        }
    }
}

/// Extract the bare SIP URI from a Contact header value.
///
/// Handles angle-bracket syntax: `<sip:user@host:5060;transport=tcp>;expires=3600`
/// → `sip:user@host:5060;transport=tcp`. Without brackets, returns the full value
/// trimmed of whitespace.
pub fn extract_contact_uri(header_value: &str) -> String {
    let trimmed = header_value.trim();
    if let Some(start) = trimmed.find('<') {
        if let Some(end) = trimmed[start..].find('>') {
            return trimmed[start + 1..start + end].to_string();
        }
    }
    // No angle brackets — take the URI part (before any header params separated by ';'
    // that are NOT URI params). For bare URIs like "sip:user@host:5060;transport=tcp",
    // the entire value is the URI.
    trimmed.to_string()
}

/// Ensure a SIP From/To header value carries a `;tag=<tag>` parameter.
///
/// `local_from_uri` and `remote_to_uri` are captured from the outbound
/// INVITE before the dialog's far end answers, so they don't yet contain
/// the dialog tag. The tag arrives separately in the 2xx response and is
/// stored as `local_tag` / `remote_tag`. In-dialog request builders must
/// reunite them so peers can match the dialog (RFC 3261 §12.2).
///
/// Idempotent: if the value already contains `;tag=` it is returned
/// unchanged. If `tag` is `None` or empty (early-dialog requests, where
/// no remote tag is established yet — RFC 3311 §5.2), the value is also
/// unchanged.
pub fn ensure_tag(header_value: &str, tag: Option<&str>) -> String {
    if header_value.contains(";tag=") {
        return header_value.to_string();
    }
    match tag {
        Some(t) if !t.is_empty() => format!("{};tag={}", header_value.trim_end(), t),
        _ => header_value.to_string(),
    }
}

/// Rewrite the host part of a SIP URI in a From/To header value.
///
/// Given a header value like `<sip:user@old-host:5060;params>;tag=...`,
/// replaces `old-host` with `new_host`. Works for both From and To headers.
pub fn rewrite_uri_host(header_value: &str, new_host: &str) -> String {
    if let Some(at_pos) = header_value.find('@') {
        let after_at = &header_value[at_pos + 1..];
        let host_end = after_at
            .find(['>', ';', ':'])
            .unwrap_or(after_at.len());
        let end_pos = at_pos + 1 + host_end;
        format!(
            "{}{}{}",
            &header_value[..at_pos + 1],
            new_host,
            &header_value[end_pos..],
        )
    } else {
        header_value.to_string()
    }
}

/// Generate a fresh SIP tag.
pub fn generate_tag() -> String {
    format!("sb-{}", &uuid::Uuid::new_v4().as_simple().to_string()[..12])
}

/// Generate a fresh Call-ID for an outbound leg.
pub fn generate_call_id() -> String {
    format!("b2b-{}", uuid::Uuid::new_v4())
}

// ---------------------------------------------------------------------------
// Transport binding (owned by each leg)
// ---------------------------------------------------------------------------

/// Network transport binding for a leg.
#[derive(Debug, Clone)]
pub struct TransportInfo {
    /// Remote peer address.
    pub remote_addr: SocketAddr,
    /// Connection ID (for TCP/TLS/WS connection reuse).
    pub connection_id: ConnectionId,
    /// Transport protocol.
    pub transport: Transport,
}

// ---------------------------------------------------------------------------
// Leg — pure state for one side of a B2BUA call
// ---------------------------------------------------------------------------

/// Per-leg state in a B2BUA call.
///
/// Each leg owns its SIP dialog state and transport binding independently.
/// Multiple B-legs can coexist (forking) with separate dialogs.
#[derive(Debug, Clone)]
pub struct Leg {
    /// Unique leg identifier.
    pub id: LegId,
    /// Which side of the B2BUA.
    pub side: LegSide,
    /// This leg's SIP dialog state.
    pub dialog: Dialog,
    /// Network transport binding.
    pub transport: TransportInfo,
    /// Via branch for this leg.
    /// A-leg: the inbound INVITE's Via branch.
    /// B-leg: our generated branch for the outbound INVITE.
    pub branch: String,
    /// Stored Via headers from re-INVITE originator (for response routing).
    pub stored_vias: Vec<String>,
    /// Stored CSeq from re-INVITE originator (for response CSeq restoration).
    pub stored_cseq: Option<String>,
    /// Whether the initial INVITE on this leg has been ACKed.
    pub initial_acked: bool,
    /// Whether a re-INVITE toward this leg is currently in flight
    /// (awaiting a final response). Used by glare detection
    /// (RFC 3261 §14.1): if a new re-INVITE arrives while one is
    /// already pending toward the same leg we respond 491 Request
    /// Pending rather than forward a second concurrent offer/answer.
    pub pending_reinvite: bool,
    /// Highest RSeq we've already PRACKed on this leg (RFC 3262
    /// auto-PRACK). Reliable 1xx responses retransmit until PRACKed
    /// — without this guard we would emit a fresh PRACK for every
    /// retransmit, racking up CSeq numbers and confusing the peer.
    pub prack_acked_rseq: Option<u32>,
    /// Last-sent outbound INVITE for this leg (B-leg only).
    /// Persisted at the end of [`b2bua_send_b_leg_invite`] so that the
    /// 401/407 auto-retry path can rebuild the retry from the fully
    /// hygiene-processed B-leg INVITE rather than the raw A-leg INVITE
    /// (which would leak A-leg headers, identity, and Record-Routes).
    pub b_leg_invite: Option<Arc<Mutex<SipMessage>>>,
    /// Inbound A-leg CANCEL arrived before this B-leg's INVITE was
    /// actually sent (b_leg_invite stash hadn't landed yet — race
    /// between the script's call.dial() actioning the outbound INVITE
    /// and the upstream CANCEL on the A-leg).  When set, the moment
    /// b_leg_invite gets stashed in b2bua_send_b_leg_invite the deferred
    /// CANCEL is emitted immediately so RFC 3261 §9.1 correlation
    /// (same Via branch + CSeq seq as the INVITE being cancelled) holds.
    pub pending_cancel: bool,
    /// Whether a 401/407 digest challenge on this leg has already driven an
    /// auth retry (B-leg only). The trunk's INVITE server transaction
    /// retransmits the challenge until it is ACKed (RFC 3261 §17.1.1.3); each
    /// retransmit re-enters the response handler on this same branch. Without
    /// this guard every retransmit would emit a fresh authenticated INVITE at
    /// the same CSeq on a new branch, which the trunk sees as a merged request
    /// (RFC 3261 §8.2.2.2) and rejects 482. Set once on the first challenge;
    /// subsequent challenges on this branch are absorbed (re-ACKed only).
    pub auth_challenged: bool,
}

impl Leg {
    /// Create a new A-leg from an inbound INVITE.
    pub fn new_a_leg(
        call_id: String,
        from_tag: String,
        branch: String,
        transport: TransportInfo,
    ) -> Self {
        Self {
            id: LegId::new(),
            side: LegSide::A,
            dialog: Dialog::from_inbound(call_id, from_tag),
            transport,
            branch,
            stored_vias: Vec::new(),
            stored_cseq: None,
            initial_acked: false,
            pending_reinvite: false,
            prack_acked_rseq: None,
            b_leg_invite: None,
            pending_cancel: false,
            auth_challenged: false,
        }
    }

    /// Create a new B-leg for an outbound INVITE.
    pub fn new_b_leg(
        call_id: String,
        local_tag: String,
        target_uri: String,
        branch: String,
        transport: TransportInfo,
    ) -> Self {
        Self {
            id: LegId::new(),
            side: LegSide::B,
            dialog: Dialog::new_outbound(call_id, local_tag, target_uri),
            transport,
            branch,
            stored_vias: Vec::new(),
            stored_cseq: None,
            initial_acked: false,
            pending_reinvite: false,
            prack_acked_rseq: None,
            b_leg_invite: None,
            pending_cancel: false,
            auth_challenged: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Per-leg status (for forking coordination)
// ---------------------------------------------------------------------------

/// Status of a B-leg in a forked call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BLegStatus {
    /// INVITE sent, waiting for response.
    Trying,
    /// Received 180/183 — ringing.
    Ringing,
    /// Received 2xx — this leg answered (winner).
    Answered,
    /// Received a final error response.
    Failed(u16),
    /// CANCEL sent (another leg won, or A-leg cancelled).
    Cancelled,
}

// ---------------------------------------------------------------------------
// LegRegistry — global routing table
// ---------------------------------------------------------------------------

/// Global registry mapping SIP identifiers to internal call IDs.
///
/// The dispatcher uses this to route inbound SIP messages to the correct
/// call actor.
#[derive(Debug)]
pub struct LegRegistry {
    /// SIP Call-ID → internal call ID (for matching inbound requests).
    by_call_id: DashMap<String, String>,
    /// Via branch → internal call ID (for matching responses).
    by_branch: DashMap<String, String>,
}

impl LegRegistry {
    pub fn new() -> Self {
        Self {
            by_call_id: DashMap::new(),
            by_branch: DashMap::new(),
        }
    }

    /// Register a SIP Call-ID → internal call ID mapping.
    pub fn register_call_id(&self, sip_call_id: &str, internal_id: &str) {
        self.by_call_id.insert(sip_call_id.to_string(), internal_id.to_string());
    }

    /// Register a Via branch → internal call ID mapping.
    pub fn register_branch(&self, branch: &str, internal_id: &str) {
        self.by_branch.insert(branch.to_string(), internal_id.to_string());
    }

    /// Look up internal call ID by SIP Call-ID.
    pub fn lookup_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.by_call_id.get(sip_call_id).map(|v| v.clone())
    }

    /// Look up internal call ID by Via branch.
    pub fn lookup_branch(&self, branch: &str) -> Option<String> {
        self.by_branch.get(branch).map(|v| v.clone())
    }

    /// Remove a SIP Call-ID mapping.
    pub fn remove_call_id(&self, sip_call_id: &str) {
        self.by_call_id.remove(sip_call_id);
    }

    /// Remove a branch mapping.
    pub fn remove_branch(&self, branch: &str) {
        self.by_branch.remove(branch);
    }

    /// Remove all mappings for a call (Call-IDs + branches).
    pub fn remove_all_for_call(&self, internal_id: &str) {
        // Remove all Call-ID mappings for this call
        self.by_call_id.retain(|_, v| v.as_str() != internal_id);
        // Remove all branch mappings for this call
        self.by_branch.retain(|_, v| v.as_str() != internal_id);
    }

    /// Number of registered calls (unique internal IDs in Call-ID map).
    pub fn call_count(&self) -> usize {
        let mut ids: Vec<String> = self.by_call_id.iter().map(|e| e.value().clone()).collect();
        ids.sort();
        ids.dedup();
        ids.len()
    }
}

impl Default for LegRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CallState
// ---------------------------------------------------------------------------

/// Per-call state tracked by the call supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    /// A-leg INVITE received, waiting for script decision.
    Calling,
    /// B-leg(s) ringing.
    Ringing,
    /// A B-leg answered — call is connected.
    Answered,
    /// Call terminated.
    Terminated,
}

// ---------------------------------------------------------------------------
// CallActor — per-call supervisor
// ---------------------------------------------------------------------------

/// Per-call supervisor managing A-leg + B-leg(s).
///
/// Each call actor owns its legs as independent entities. The dispatcher
/// accesses call actors via `DashMap<String, CallActor>` and operates on
/// the leg state directly.
///
/// ## Forking Support
///
/// Multiple B-legs can be active simultaneously. The call actor tracks
/// per-leg status and coordinates:
/// - Winner selection (first 2xx)
/// - Loser cancellation
/// - Partial teardown (BYE from one B-leg doesn't tear down others)
///
/// ## Future: API-Driven Calls
///
/// Call actors can be created without an inbound INVITE, enabling
/// API-driven call origination. Create a `CallActor`, add legs, and
/// the system sends INVITEs on your behalf.
#[derive(Debug)]
pub struct CallActor {
    /// Internal call identifier (UUID).
    pub id: String,
    /// Current call state.
    pub state: CallState,
    /// The inbound (A) leg.
    pub a_leg: Leg,
    /// The outbound (B) leg(s) — one per fork target.
    pub b_legs: Vec<Leg>,
    /// Per-B-leg status (parallel vector with b_legs).
    pub b_leg_status: Vec<BLegStatus>,
    /// Per-B-leg actor handles (parallel vector with b_legs).
    /// `None` until the actor is spawned for that leg.
    pub b_leg_handles: Vec<Option<LegHandle>>,
    /// Event channel sender — shared by all B-leg actors for this call.
    /// Created when the call is established; `None` until then.
    pub event_tx: Option<tokio::sync::mpsc::Sender<CallEvent>>,
    /// Index of the winning B-leg (after 2xx answer).
    pub winner: Option<usize>,
    /// When the call was created.
    pub created_at: std::time::Instant,
    /// Original A-leg INVITE message (for script handler reconstruction).
    pub a_leg_invite: Option<Arc<Mutex<SipMessage>>>,
    /// RFC 4028 session timer state (set after 200 OK negotiation).
    pub session_timer: Option<SessionTimerState>,
    /// Per-call session timer override from Python script.
    pub session_timer_override: Option<crate::script::api::call::SessionTimerOverride>,
    /// Active transfer context (REFER handling).
    pub transfer: Option<super::transfer::TransferContext>,
    /// Outbound digest credentials for B-leg 401/407 retry.
    pub outbound_credentials: Option<(String, String)>,
    /// Per-call digest nonce-count tracker (RFC 7616 §3.3). Resets to 1 when
    /// the trunk challenges with a fresh nonce; increments when the same
    /// nonce is reused (e.g. authenticated re-INVITE inside the dialog).
    pub digest_nc: crate::auth::NonceCounter,
    /// Whether li.record() was called — SIPREC recording via config SRS URI.
    pub li_record: bool,
    /// When true, copy the A-leg Call-ID to B-leg(s).
    pub preserve_call_id: bool,
    /// Script-pinned B-leg From URI host (`call.set_from_host()`). When set,
    /// the B-leg INVITE From host is rewritten to this instead of the B2BUA
    /// advertised address — opts out of From topology-hiding for multitenant
    /// edges that key the tenant on the From domain.
    pub from_host_override: Option<String>,
    /// Script-pinned B-leg To URI host (`call.set_to_host()`). When set, the
    /// B-leg INVITE To host is rewritten to this instead of the dial-target host.
    pub to_host_override: Option<String>,
    /// Pre-built ACK for the winning B-leg, deferred until A-leg ACKs (late ACK pattern).
    /// Contains (ACK message, transport, destination address).
    pub pending_b_leg_ack: Option<(SipMessage, crate::transport::Transport, std::net::SocketAddr)>,
    /// Resolved header policy for this call (preset + per-call deltas) — set
    /// when the script calls `call.dial(header_policy=…)`.  When `None`, the
    /// dispatcher falls back to the configured `b2bua.default_header_policy`.
    pub resolved_header_policy: Option<std::sync::Arc<super::header_policy::ResolvedPolicy>>,
    /// Whether the A-leg *peer* advertised `100rel` on the wire (RFC 3262 §3),
    /// snapshotted at INVITE receipt **before** the `@b2bua.on_invite` handler
    /// runs.  Drives the reliable-1xx strip in `sanitize_b2bua_response`.  This
    /// MUST NOT be re-derived from `a_leg_invite`: the script can mutate that
    /// shared message via `call.set_header("Supported", "…100rel")` to advertise
    /// reliable provisionals toward the B-leg (IR.92 UEs need it to alert), and
    /// reading it back would falsely conclude the A-leg trunk supports `100rel`,
    /// leaking the reliable provisional to a peer that CANCELs it.
    pub a_leg_supports_100rel: bool,
    /// Number of credentialed outbound INVITEs already sent on the 401/407
    /// auto-retry path for this call. Capped (see `MAX_B2BUA_AUTH_RETRIES` in
    /// the dispatcher): once the cap is hit, a further challenge is treated as a
    /// persistent auth failure and surfaced upstream rather than re-authed.
    /// Counts committed retries only (one per retry leg) — retransmitted
    /// challenges are absorbed by the per-leg [`Leg::auth_challenged`] guard
    /// before they reach the counter, so the cap reflects real attempts.
    pub auth_retry_count: u32,
    /// Wall-clock deadline by which this call must be answered, set from the
    /// script's `call.fork(timeout=…)` / `call.dial(timeout=…)` when the B-leg
    /// INVITE(s) go out. The orphan sweep fails the call (CANCEL pending legs,
    /// `@b2bua.on_failure`, `408` to the A-leg, teardown) once this passes while
    /// the call is still un-answered. `None` = no application timeout (the 24h
    /// orphan backstop still applies).
    pub answer_deadline: Option<std::time::Instant>,
}

impl CallActor {
    /// Create a new call actor with an A-leg.
    pub fn new(a_leg: Leg) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            state: CallState::Calling,
            a_leg,
            b_legs: Vec::new(),
            b_leg_status: Vec::new(),
            b_leg_handles: Vec::new(),
            event_tx: None,
            winner: None,
            created_at: std::time::Instant::now(),
            a_leg_invite: None,
            session_timer: None,
            session_timer_override: None,
            transfer: None,
            outbound_credentials: None,
            digest_nc: crate::auth::NonceCounter::new(),
            li_record: false,
            preserve_call_id: false,
            from_host_override: None,
            to_host_override: None,
            pending_b_leg_ack: None,
            resolved_header_policy: None,
            a_leg_supports_100rel: false,
            auth_retry_count: 0,
            answer_deadline: None,
        }
    }

    /// Add a B-leg to this call.
    pub fn add_b_leg(&mut self, leg: Leg) -> usize {
        let index = self.b_legs.len();
        self.b_legs.push(leg);
        self.b_leg_status.push(BLegStatus::Trying);
        self.b_leg_handles.push(None);
        index
    }

    /// Remove a B-leg by index (e.g. after re-INVITE completion).
    pub fn remove_b_leg(&mut self, index: usize) -> Option<Leg> {
        if index < self.b_legs.len() {
            self.b_leg_status.remove(index);
            self.b_leg_handles.remove(index);
            // Adjust winner index if needed
            if let Some(ref mut w) = self.winner {
                if *w == index {
                    self.winner = None;
                } else if *w > index {
                    *w -= 1;
                }
            }
            Some(self.b_legs.remove(index))
        } else {
            None
        }
    }

    /// Supersede a B-leg in place (e.g. a 401/407 digest or RFC 4028 422
    /// session-timer retry resends the INVITE on a fresh branch).
    ///
    /// RFC 3261 §9.1: the failed attempt's INVITE client transaction is
    /// complete once it has received a final response and been ACKed, so the
    /// retry is the *same* logical B-leg continuing with new credentials /
    /// Session-Expires — NOT a new fork branch. Appending instead (the old
    /// behaviour) leaves the dead leg in `b_legs`, so a later CANCEL fans out
    /// to its already-final-responded transaction as well as the live one
    /// (→ a spurious 481 Call/Transaction Does Not Exist).
    ///
    /// Replaces the leg at `index`, resets its status to `Trying`, and clears
    /// the actor handle — dropping the old [`LegHandle`] closes the previous
    /// [`LegActor`]'s channel so it exits on its own (the same implicit
    /// cleanup [`remove_b_leg`](Self::remove_b_leg) relies on). Keeps the
    /// `b_legs` / `b_leg_status` / `b_leg_handles` parallel vectors aligned.
    ///
    /// Returns the superseded leg's Via branch (so the caller can re-point the
    /// routing registry from the old branch to the new one), or `None` if
    /// `index` is out of range.
    pub fn replace_b_leg(&mut self, index: usize, leg: Leg) -> Option<String> {
        if index < self.b_legs.len() {
            let old_branch = std::mem::replace(&mut self.b_legs[index], leg).branch;
            self.b_leg_status[index] = BLegStatus::Trying;
            self.b_leg_handles[index] = None;
            Some(old_branch)
        } else {
            None
        }
    }

    /// Get the winning B-leg (if any).
    pub fn winning_b_leg(&self) -> Option<&Leg> {
        self.winner.and_then(|i| self.b_legs.get(i))
    }

    /// Get the winning B-leg mutably.
    pub fn winning_b_leg_mut(&mut self) -> Option<&mut Leg> {
        self.winner.and_then(|i| self.b_legs.get_mut(i))
    }

    /// Find a B-leg by its Via branch.
    pub fn find_b_leg_by_branch(&self, branch: &str) -> Option<(usize, &Leg)> {
        self.b_legs.iter().enumerate().find(|(_, leg)| leg.branch == branch)
    }

    /// Find a B-leg mutably by its Via branch.
    pub fn find_b_leg_by_branch_mut(&mut self, branch: &str) -> Option<(usize, &mut Leg)> {
        self.b_legs.iter_mut().enumerate().find(|(_, leg)| leg.branch == branch)
    }

    /// Set the winner and update call state.
    pub fn set_winner(&mut self, index: usize) {
        self.winner = Some(index);
        self.state = CallState::Answered;
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Answered;
        }
    }

    /// Check if a BYE from a specific B-leg should tear down the A-leg.
    ///
    /// In a forking scenario, only the winning B-leg's BYE tears down the call.
    /// BYEs from non-winning legs (which shouldn't normally happen after CANCEL)
    /// are absorbed.
    pub fn should_teardown_on_b_bye(&self, b_leg_index: usize) -> bool {
        self.winner == Some(b_leg_index)
    }

    /// Mark a B-leg as failed and return the best action.
    ///
    /// Returns true if all B-legs have settled (all failed/cancelled/answered).
    pub fn mark_b_leg_failed(&mut self, index: usize, status_code: u16) -> bool {
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Failed(status_code);
        }
        self.all_b_legs_settled()
    }

    /// Mark a B-leg as cancelled.
    pub fn mark_b_leg_cancelled(&mut self, index: usize) {
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Cancelled;
        }
    }

    /// Mark a B-leg as ringing.
    pub fn mark_b_leg_ringing(&mut self, index: usize) {
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Ringing;
        }
    }

    /// Whether we've already forwarded a ringing indication to the A-leg.
    pub fn any_b_leg_ringing(&self) -> bool {
        self.b_leg_status.iter().any(|s| matches!(s, BLegStatus::Ringing | BLegStatus::Answered))
    }

    /// Check if all B-legs have reached a terminal state.
    pub fn all_b_legs_settled(&self) -> bool {
        self.b_leg_status.iter().all(|s| {
            matches!(s, BLegStatus::Answered | BLegStatus::Failed(_) | BLegStatus::Cancelled)
        })
    }

    /// Get the highest-priority error code among failed B-legs.
    pub fn best_error_code(&self) -> u16 {
        self.b_leg_status
            .iter()
            .filter_map(|s| match s {
                BLegStatus::Failed(code) => Some(*code),
                _ => None,
            })
            .max_by(|a, b| error_priority(*a).cmp(&error_priority(*b)))
            .unwrap_or(500)
    }

    /// Indices of non-winning B-legs that should be cancelled.
    pub fn losers(&self, winner_index: usize) -> Vec<usize> {
        (0..self.b_legs.len())
            .filter(|&i| i != winner_index)
            .filter(|&i| {
                matches!(
                    self.b_leg_status.get(i),
                    Some(BLegStatus::Trying | BLegStatus::Ringing)
                )
            })
            .collect()
    }

    /// Check if the message came from the A-leg (by source address).
    pub fn is_from_a_leg(&self, source_addr: SocketAddr) -> bool {
        self.a_leg.transport.remote_addr == source_addr
    }

    /// Store the original A-leg INVITE message.
    pub fn set_a_leg_invite(&mut self, message: Arc<Mutex<SipMessage>>) {
        self.a_leg_invite = Some(message);
    }

    /// Set session timer state.
    pub fn set_session_timer(&mut self, timer: SessionTimerState) {
        self.session_timer = Some(timer);
    }

    /// Reset session timer's last_refresh.
    pub fn reset_session_timer(&mut self) {
        if let Some(ref mut timer) = self.session_timer {
            timer.last_refresh = std::time::Instant::now();
        }
    }

    /// Set the actor handle for a B-leg.
    pub fn set_b_leg_handle(&mut self, index: usize, handle: LegHandle) {
        if index < self.b_leg_handles.len() {
            self.b_leg_handles[index] = Some(handle);
        }
    }

    /// Send `Shutdown` to all active B-leg actor handles.
    pub fn shutdown_actors(&self) {
        for handle in self.b_leg_handles.iter().flatten() {
            let _ = handle.tx.try_send(LegMessage::Shutdown);
        }
    }
}

/// Priority score for error response codes.
fn error_priority(code: u16) -> u32 {
    let class_weight = match code {
        600..=699 => 3000,
        500..=599 => 2000,
        400..=499 => 1000,
        300..=399 => 0,
        _ => 0,
    };
    class_weight + code as u32
}

// ---------------------------------------------------------------------------
// CallActorStore — manages all active calls
// ---------------------------------------------------------------------------

/// Lightweight state kept after call teardown so retransmitted re-INVITE
/// 200 OKs can still be ACKed (RFC 3261 §13.2.2.4).
///
/// When BYE removes a call, any `reinvite_done:` B-leg entries are moved
/// here. Entries auto-expire after 32 seconds (Timer H).
#[derive(Debug, Clone)]
pub struct ZombieReInviteEntry {
    /// Where to send the ACK.
    pub destination: SocketAddr,
    /// Transport protocol for the ACK.
    pub transport: Transport,
}

/// Post-teardown state for a B-leg whose INVITE was CANCELled but might still
/// be answered (RFC 3261 §9.1 glare): the callee put a 2xx on the wire before
/// our CANCEL arrived. That 2xx still establishes a dialog, which the B2BUA
/// MUST ACK (§13.2.2.4) and then BYE (§15) to release. `handle_b2bua_cancel`
/// removes the call — unregistering the B-leg branch — so the racing 2xx would
/// otherwise be dropped as "unknown branch"; this entry lets `handle_response`
/// catch it and clean the dialog up.
///
/// Keyed by B-leg SIP Call-ID. Auto-expires after 32 seconds (Timer H).
#[derive(Debug, Clone)]
pub struct ZombieCancelledLeg {
    /// The cancelled B-leg's dialog + transport, used to build the ACK and BYE.
    /// `remote_tag` / `remote_contact` are filled from the racing 2xx at
    /// handling time (they were unknown when the INVITE was CANCELled).
    pub leg: Leg,
    /// Whether the BYE has already been sent. The first racing 2xx triggers
    /// ACK + BYE; later 200 OK retransmits re-ACK only (so a lost ACK still
    /// gets retried) without emitting a second BYE.
    pub byed: bool,
}

/// Manages all active B2BUA calls.
///
/// Stores `CallActor` instances in a concurrent map, indexed by internal
/// call ID. Uses `LegRegistry` for SIP-level routing.
#[derive(Debug)]
pub struct CallActorStore {
    /// Internal call ID → CallActor.
    calls: DashMap<String, CallActor>,
    /// SIP identifier routing table.
    pub registry: LegRegistry,
    /// Post-teardown re-INVITE ACK absorber, keyed by B-leg SIP Call-ID.
    pub zombie_reinvites: DashMap<String, ZombieReInviteEntry>,
    /// Post-CANCEL glare absorber (RFC 3261 §9.1): a 2xx that raced our CANCEL
    /// is ACKed + BYEd here, keyed by B-leg SIP Call-ID.
    pub zombie_cancelled: DashMap<String, ZombieCancelledLeg>,
}

impl CallActorStore {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
            registry: LegRegistry::new(),
            zombie_reinvites: DashMap::new(),
            zombie_cancelled: DashMap::new(),
        }
    }

    /// Number of active calls.
    pub fn count(&self) -> usize {
        self.calls.len()
    }

    /// Create a new call from an A-leg and return the internal call ID.
    ///
    /// Registers the A-leg's SIP Call-ID in the registry.
    pub fn create_call(&self, a_leg: Leg) -> String {
        let sip_call_id = a_leg.dialog.call_id.clone();
        let a_branch = a_leg.branch.clone();
        let call = CallActor::new(a_leg);
        let id = call.id.clone();
        self.registry.register_call_id(&sip_call_id, &id);
        self.registry.register_branch(&a_branch, &id);
        self.calls.insert(id.clone(), call);
        id
    }

    /// Add a B-leg to a call. Registers branch in the registry.
    pub fn add_b_leg(&self, call_id: &str, leg: Leg) -> bool {
        let branch = leg.branch.clone();
        let sip_call_id = leg.dialog.call_id.clone();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.add_b_leg(leg);
            self.registry.register_branch(&branch, call_id);
            // Only register Call-ID if not already mapped to this call.
            // Re-INVITE tracking legs reuse the A-leg or B-leg Call-ID;
            // re-registering would overwrite the original mapping, and
            // remove_b_leg would then delete it, breaking BYE routing.
            if self.registry.lookup_call_id(&sip_call_id).as_deref() != Some(call_id) {
                self.registry.register_call_id(&sip_call_id, call_id);
            }
            true
        } else {
            false
        }
    }

    /// Supersede a B-leg in place and re-point the routing registry from the
    /// old branch to the new one.
    ///
    /// Used by the 401/407 (RFC 3261 §9.1) and 422 (RFC 4028) retry paths: the
    /// retry continues the same logical B-leg rather than forking a new one, so
    /// a later CANCEL fans out to the live transaction only. See
    /// [`CallActor::replace_b_leg`]. The dialog Call-ID is unchanged (the retry
    /// reuses it), so the Call-ID registration is left untouched. Returns true
    /// on success, false if the call or `index` is unknown.
    pub fn replace_b_leg(&self, call_id: &str, index: usize, leg: Leg) -> bool {
        let new_branch = leg.branch.clone();
        let old_branch = match self.calls.get_mut(call_id) {
            Some(mut call) => call.replace_b_leg(index, leg),
            None => return false,
        };
        match old_branch {
            Some(old) => {
                if old != new_branch {
                    self.registry.remove_branch(&old);
                }
                self.registry.register_branch(&new_branch, call_id);
                true
            }
            None => false,
        }
    }

    /// Remove a B-leg by index.
    pub fn remove_b_leg(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(removed) = call.remove_b_leg(index) {
                self.registry.remove_branch(&removed.branch);
                // Only remove Call-ID mapping if no other leg uses it.
                // Re-INVITE tracking legs share the A-leg or winning B-leg
                // Call-ID; removing it here would break BYE/in-dialog routing.
                let cid = &removed.dialog.call_id;
                let still_used = call.a_leg.dialog.call_id == *cid
                    || call.b_legs.iter().any(|b| b.dialog.call_id == *cid);
                if !still_used {
                    self.registry.remove_call_id(cid);
                }
            }
        }
    }

    /// Update the target_uri of a B-leg (used to mark re-INVITE entries as done).
    pub fn set_b_leg_target_uri(&self, call_id: &str, index: usize, target_uri: String) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(b_leg) = call.b_legs.get_mut(index) {
                b_leg.dialog.target_uri = Some(target_uri);
            }
        }
    }

    /// Find any call that contains a leg matching the supplied dialog
    /// triple. Used to validate the `Replaces` header on an incoming
    /// INVITE (RFC 3891 §3): the referenced dialog must exist or the
    /// INVITE MUST be rejected with 481 Call/Transaction Does Not
    /// Exist.
    ///
    /// The `from_tag` in the `Replaces` header is the tag of the UA
    /// that *sent* the original dialog request (the "remote" side from
    /// our perspective); `to_tag` is *our* tag for that dialog.
    pub fn find_call_by_replaces_dialog(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<String> {
        for entry in self.calls.iter() {
            let call = entry.value();
            let leg_matches = |leg: &Leg| {
                leg.dialog.call_id == call_id
                    && leg.dialog.local_tag == to_tag
                    && (leg
                        .dialog
                        .remote_tag
                        .as_deref() == Some(from_tag))
            };
            if leg_matches(&call.a_leg) || call.b_legs.iter().any(leg_matches) {
                return Some(entry.key().clone());
            }
        }
        None
    }

    /// Atomically increment the local CSeq counter on the A-leg or the
    /// winning B-leg and return the new value. Used when the B2BUA needs
    /// to originate an in-dialog request (PRACK, BYE, re-INVITE) and must
    /// allocate a CSeq number that is monotonically increasing within
    /// the dialog (RFC 3261 §12.2.1.1).
    pub fn next_local_cseq(&self, call_id: &str, on_a_leg: bool) -> Option<u32> {
        let mut call = self.calls.get_mut(call_id)?;
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            // Two-step indirection because `winner` borrows `call` immutably
            // while `b_legs.get_mut` needs the mutable borrow exclusively.
            let idx = call.winner?;
            call.b_legs.get_mut(idx)
        };
        leg.map(|leg| {
            leg.dialog.local_cseq = leg.dialog.local_cseq.saturating_add(1);
            leg.dialog.local_cseq
        })
    }

    /// Like `next_local_cseq` but addresses a specific B-leg by index —
    /// used when the call hasn't picked a winner yet (e.g. early media on
    /// a forked INVITE where the 1xx arrives before any 2xx).
    pub fn next_b_leg_local_cseq(&self, call_id: &str, b_leg_index: usize) -> Option<u32> {
        let mut call = self.calls.get_mut(call_id)?;
        let leg = call.b_legs.get_mut(b_leg_index)?;
        leg.dialog.local_cseq = leg.dialog.local_cseq.saturating_add(1);
        Some(leg.dialog.local_cseq)
    }

    /// RFC 3262 auto-PRACK dedup: returns `true` exactly once for each
    /// new RSeq value seen on the given B-leg, and `false` for retransmits
    /// of an already-PRACKed reliable provisional. Used so the B2BUA emits
    /// a single PRACK per RSeq instead of one per 1xx retransmit.
    pub fn try_mark_prack_acked(
        &self,
        call_id: &str,
        b_leg_index: usize,
        rseq: u32,
    ) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let Some(leg) = call.b_legs.get_mut(b_leg_index) else {
            return false;
        };
        if leg.prack_acked_rseq.is_some_and(|v| v >= rseq) {
            return false;
        }
        leg.prack_acked_rseq = Some(rseq);
        true
    }

    /// 401/407 auth-retry dedup: returns `true` exactly once for the first
    /// digest challenge seen on the given B-leg, and `false` for retransmits
    /// of that challenge on the same branch. The trunk retransmits the 401/407
    /// until it is ACKed (RFC 3261 §17.1.1.3); without this guard each
    /// retransmit would emit a second authenticated INVITE at the same CSeq on
    /// a new branch, which the trunk rejects as a merged request (§8.2.2.2 →
    /// 482). A chained re-challenge (e.g. stale nonce) lands on the *retry*
    /// leg's branch, which is a distinct B-leg with its own flag, so legitimate
    /// re-authentication still proceeds.
    pub fn try_mark_auth_challenged(&self, call_id: &str, b_leg_index: usize) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let Some(leg) = call.b_legs.get_mut(b_leg_index) else {
            return false;
        };
        if leg.auth_challenged {
            return false;
        }
        leg.auth_challenged = true;
        true
    }

    /// Current count of credentialed outbound INVITEs sent on the 401/407
    /// auto-retry path for this call (0 if the call is unknown). Read by the
    /// dispatcher's retry cap before deciding whether to re-auth or surface the
    /// failure.
    pub fn auth_retry_count(&self, call_id: &str) -> u32 {
        self.calls.get(call_id).map_or(0, |call| call.auth_retry_count)
    }

    /// Increment and return the per-call credentialed-retry counter. Called
    /// once per committed retry (after the per-leg dedup), so retransmitted
    /// challenges don't inflate it.
    pub fn incr_auth_retry_count(&self, call_id: &str) -> u32 {
        match self.calls.get_mut(call_id) {
            Some(mut call) => {
                call.auth_retry_count = call.auth_retry_count.saturating_add(1);
                call.auth_retry_count
            }
            None => 0,
        }
    }

    /// Set the `pending_reinvite` flag on the A-leg or the winning B-leg.
    ///
    /// Returns the previous value so callers can implement the RFC 3261
    /// §14.1 glare check in one step: take-and-check if there was already
    /// a pending re-INVITE toward this leg.
    pub fn set_pending_reinvite(&self, call_id: &str, on_a_leg: bool, pending: bool) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            call.winner.and_then(|idx| call.b_legs.get_mut(idx))
        };
        match leg {
            Some(leg) => {
                let previous = leg.pending_reinvite;
                leg.pending_reinvite = pending;
                previous
            }
            None => false,
        }
    }

    /// Look up internal call ID by SIP Call-ID.
    pub fn find_by_sip_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.registry.lookup_call_id(sip_call_id)
    }

    /// Look up internal call ID by Via branch.
    pub fn call_id_for_branch(&self, branch: &str) -> Option<String> {
        self.registry.lookup_branch(branch)
    }

    /// Get a call by internal ID.
    pub fn get_call(&self, call_id: &str) -> Option<dashmap::mapref::one::Ref<'_, String, CallActor>> {
        self.calls.get(call_id)
    }

    /// Get a mutable reference to a call.
    pub fn get_call_mut(&self, call_id: &str) -> Option<dashmap::mapref::one::RefMut<'_, String, CallActor>> {
        self.calls.get_mut(call_id)
    }

    /// Set call state.
    pub fn set_state(&self, call_id: &str, state: CallState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.state = state;
        }
    }

    /// Set the winning B-leg.
    pub fn set_winner(&self, call_id: &str, index: usize) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_winner(index);
        }
    }

    /// Store the original A-leg INVITE.
    pub fn set_a_leg_invite(&self, call_id: &str, message: Arc<Mutex<SipMessage>>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_a_leg_invite(message);
        }
    }

    /// Set session timer state.
    pub fn set_session_timer(&self, call_id: &str, timer: SessionTimerState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.set_session_timer(timer);
        }
    }

    /// Reset session timer.
    pub fn reset_session_timer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.reset_session_timer();
        }
    }

    /// Set transfer context.
    pub fn set_transfer(&self, call_id: &str, transfer: super::transfer::TransferContext) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = Some(transfer);
        }
    }

    /// Clear transfer context.
    pub fn clear_transfer(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.transfer = None;
        }
    }

    /// Remove a call and clean up all registry entries.
    ///
    /// Sends `Shutdown` to all active B-leg actor handles before removing.
    /// B-leg entries with `reinvite_done:` or `reinvite:` target_uri are moved
    /// to `zombie_reinvites` so retransmitted 200 OKs can still be ACKed.
    pub fn remove_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            // Shutdown any active B-leg actors
            call.shutdown_actors();
            // Clean up A-leg registry entries
            self.registry.remove_call_id(&call.a_leg.dialog.call_id);
            self.registry.remove_branch(&call.a_leg.branch);
            // Clean up B-leg registry entries, preserving re-INVITE state
            for b_leg in &call.b_legs {
                self.registry.remove_call_id(&b_leg.dialog.call_id);
                self.registry.remove_branch(&b_leg.branch);
                // Move re-INVITE tracking entries to zombie map
                if let Some(ref target) = b_leg.dialog.target_uri {
                    if target.starts_with("reinvite_done:") || target.starts_with("reinvite:") {
                        self.zombie_reinvites.insert(
                            b_leg.dialog.call_id.clone(),
                            ZombieReInviteEntry {
                                destination: b_leg.transport.remote_addr,
                                transport: b_leg.transport.transport,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Look up a zombie re-INVITE entry by SIP Call-ID.
    pub fn get_zombie_reinvite(&self, sip_call_id: &str) -> Option<ZombieReInviteEntry> {
        self.zombie_reinvites.get(sip_call_id).map(|e| e.clone())
    }

    /// Remove a zombie re-INVITE entry.
    pub fn remove_zombie_reinvite(&self, sip_call_id: &str) {
        self.zombie_reinvites.remove(sip_call_id);
    }

    /// Tear down a CANCELled call, but first preserve every still-pending
    /// B-leg (INVITE sent, no final response yet — status `Trying`/`Ringing`)
    /// as a [`ZombieCancelledLeg`] so a 2xx that raced the CANCEL
    /// (RFC 3261 §9.1) can still be ACKed (§13.2.2.4) and BYEd (§15) after the
    /// call is gone. Used by `handle_b2bua_cancel` in place of `remove_call`.
    ///
    /// Returns true if any zombie-cancelled entries were captured (so the
    /// caller can schedule their expiry).
    pub fn remove_call_after_cancel(&self, call_id: &str) -> bool {
        let mut captured = false;
        if let Some(call) = self.calls.get(call_id) {
            for (index, b_leg) in call.b_legs.iter().enumerate() {
                let pending = matches!(
                    call.b_leg_status.get(index),
                    Some(BLegStatus::Trying) | Some(BLegStatus::Ringing)
                );
                // Only legs whose INVITE actually went on the wire can answer.
                if pending && b_leg.b_leg_invite.is_some() {
                    self.zombie_cancelled.insert(
                        b_leg.dialog.call_id.clone(),
                        ZombieCancelledLeg {
                            leg: b_leg.clone(),
                            byed: false,
                        },
                    );
                    captured = true;
                }
            }
        }
        self.remove_call(call_id);
        captured
    }

    /// Resolve a racing 2xx to a CANCELled B-leg by SIP Call-ID.
    ///
    /// Returns the captured leg plus a `first_2xx` flag: the first racing 2xx
    /// for a Call-ID returns `(leg, true)` so the caller sends ACK + BYE; later
    /// 200 OK retransmits return `(leg, false)` so the caller re-ACKs only (a
    /// lost ACK still gets retried) without a second BYE. The entry stays until
    /// the 32 s cleanup so retransmits keep matching.
    pub fn zombie_cancelled_for_2xx(&self, sip_call_id: &str) -> Option<(Leg, bool)> {
        self.zombie_cancelled.get_mut(sip_call_id).map(|mut entry| {
            let first_2xx = !entry.byed;
            entry.byed = true;
            (entry.leg.clone(), first_2xx)
        })
    }

    /// Iterate over all active calls (for session timer sweep).
    pub fn iter_calls(&self) -> dashmap::iter::Iter<'_, String, CallActor> {
        self.calls.iter()
    }

    /// Find a call matching a Replaces header (for attended transfer).
    pub fn find_by_replaces(
        &self,
        replaces_call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<String> {
        for entry in self.calls.iter() {
            if crate::b2bua::transfer::replaces_matches(
                &crate::sip::headers::refer::Replaces {
                    call_id: replaces_call_id.to_string(),
                    from_tag: from_tag.to_string(),
                    to_tag: to_tag.to_string(),
                    early_only: false,
                },
                &entry.a_leg.dialog.call_id,
                entry.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                from_tag,
            ) {
                return Some(entry.id.clone());
            }
        }
        None
    }

    /// Sweep stale calls older than the given duration.
    pub fn sweep_stale(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let stale_ids: Vec<String> = self.calls.iter()
            .filter(|entry| now.duration_since(entry.created_at) > max_age)
            .map(|entry| entry.id.clone())
            .collect();
        let removed = stale_ids.len();
        for call_id in stale_ids {
            self.remove_call(&call_id);
        }
        removed
    }

    /// Set the answer deadline for a call (from `call.fork`/`dial` `timeout=`).
    pub fn set_answer_deadline(&self, call_id: &str, deadline: std::time::Instant) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.answer_deadline = Some(deadline);
        }
    }

    /// Internal call IDs of calls that have blown their answer deadline while
    /// still un-answered (`Calling`/`Ringing`).
    ///
    /// Does NOT remove them — the dispatcher runs the full timeout teardown
    /// (CANCEL pending legs, `@b2bua.on_failure`, `408` to the A-leg) which
    /// needs the call state and the Python engine. Answered/terminated calls
    /// and calls without a deadline are skipped, so a long answered call (whose
    /// `created_at` is old but which is past `Answered`) is never touched.
    pub fn take_timed_out_calls(&self, now: std::time::Instant) -> Vec<String> {
        self.calls.iter()
            .filter(|entry| {
                matches!(entry.state, CallState::Calling | CallState::Ringing)
                    && entry.answer_deadline.is_some_and(|deadline| now >= deadline)
            })
            .map(|entry| entry.id.clone())
            .collect()
    }
}

impl Default for CallActorStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// LegActor — async actor for B-leg message classification
// ---------------------------------------------------------------------------

/// Messages sent to a leg actor's mailbox (for async mode).
///
/// `large_enum_variant` is intentionally allowed: `SipInbound` is the hot,
/// overwhelmingly-common variant (one per inbound SIP message on the leg),
/// while `Cancel`/`Shutdown` are rare one-shots. Boxing `SipInbound.message`
/// to shrink the enum would add a heap allocation to the hot path purely to
/// save stack space on the rare variants — the opposite of what this lint
/// optimizes for.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum LegMessage {
    /// A SIP message arrived from the network.
    SipInbound {
        message: SipMessage,
        source: TransportInfo,
    },
    /// Cancel this leg.
    Cancel,
    /// Shut down.
    Shutdown,
}

/// Events from a leg actor back to the call supervisor.
#[derive(Debug)]
pub enum CallEvent {
    /// Provisional response (1xx).
    Provisional { leg_id: LegId, status_code: u16, message: SipMessage },
    /// Success response (2xx).
    Answered { leg_id: LegId, message: SipMessage },
    /// Error response (3xx-6xx).
    Failed { leg_id: LegId, status_code: u16, message: SipMessage },
    /// BYE received.
    Bye { leg_id: LegId, from_side: LegSide, message: SipMessage },
    /// re-INVITE received.
    ReInvite { leg_id: LegId, message: SipMessage },
    /// REFER received.
    Refer { leg_id: LegId, message: SipMessage },
    /// Leg actor terminated.
    Terminated { leg_id: LegId },
}

/// Async leg actor — wraps a `Leg` + channels for SIP message classification.
///
/// Receives inbound SIP messages via [`LegMessage`] and emits classified
/// [`CallEvent`]s back to the dispatcher for orchestration.
pub struct LegActor {
    /// The leg's state.
    pub leg: Leg,
    /// Mailbox receiver.
    rx: tokio::sync::mpsc::Receiver<LegMessage>,
    /// Event sender to call supervisor.
    call_tx: tokio::sync::mpsc::Sender<CallEvent>,
}

/// Handle to an async leg actor.
#[derive(Debug, Clone)]
pub struct LegHandle {
    /// Leg identifier.
    pub id: LegId,
    /// Side.
    pub side: LegSide,
    /// Channel to send messages to the leg actor.
    pub tx: tokio::sync::mpsc::Sender<LegMessage>,
}

impl LegActor {
    /// Create a new leg actor. Returns `(actor, handle)`.
    pub fn new(
        leg: Leg,
        call_tx: tokio::sync::mpsc::Sender<CallEvent>,
    ) -> (Self, LegHandle) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let handle = LegHandle {
            id: leg.id.clone(),
            side: leg.side,
            tx,
        };
        let actor = Self { leg, rx, call_tx };
        (actor, handle)
    }

    /// Run the leg actor's message processing loop.
    pub async fn run(mut self) {
        debug!(
            leg_id = %self.leg.id,
            side = ?self.leg.side,
            call_id = %self.leg.dialog.call_id,
            "leg actor started"
        );

        while let Some(msg) = self.rx.recv().await {
            match msg {
                LegMessage::SipInbound { message, source: _ } => {
                    self.handle_sip_inbound(message).await;
                }
                LegMessage::Cancel => {
                    debug!(leg_id = %self.leg.id, "leg cancelled");
                    break;
                }
                LegMessage::Shutdown => {
                    debug!(leg_id = %self.leg.id, "leg shutting down");
                    break;
                }
            }
        }

        let _ = self.call_tx.send(CallEvent::Terminated {
            leg_id: self.leg.id.clone(),
        }).await;

        debug!(leg_id = %self.leg.id, "leg actor stopped");
    }

    async fn handle_sip_inbound(&mut self, message: SipMessage) {
        use crate::sip::message::Method;

        let method = message.method().cloned();
        let status = message.status_code();

        match (method, status) {
            (_, Some(code)) => {
                if (100..200).contains(&code) {
                    let _ = self.call_tx.send(CallEvent::Provisional {
                        leg_id: self.leg.id.clone(),
                        status_code: code,
                        message,
                    }).await;
                } else if (200..300).contains(&code) {
                    if let Some(to_tag) = extract_to_tag(&message) {
                        self.leg.dialog.remote_tag = Some(to_tag);
                    }
                    let _ = self.call_tx.send(CallEvent::Answered {
                        leg_id: self.leg.id.clone(),
                        message,
                    }).await;
                } else {
                    let _ = self.call_tx.send(CallEvent::Failed {
                        leg_id: self.leg.id.clone(),
                        status_code: code,
                        message,
                    }).await;
                }
            }
            (Some(Method::Bye), _) => {
                let _ = self.call_tx.send(CallEvent::Bye {
                    leg_id: self.leg.id.clone(),
                    from_side: self.leg.side,
                    message,
                }).await;
            }
            (Some(Method::Invite), _) => {
                let _ = self.call_tx.send(CallEvent::ReInvite {
                    leg_id: self.leg.id.clone(),
                    message,
                }).await;
            }
            (Some(Method::Refer), _) => {
                let _ = self.call_tx.send(CallEvent::Refer {
                    leg_id: self.leg.id.clone(),
                    message,
                }).await;
            }
            _ => {}
        }
    }
}

/// Extract the To-tag from a SIP message.
pub fn extract_to_tag(message: &SipMessage) -> Option<String> {
    message.headers.get("To")
        .or_else(|| message.headers.get("t"))
        .and_then(|to| {
            to.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_transport() -> TransportInfo {
        TransportInfo {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        }
    }

    fn make_a_leg() -> Leg {
        Leg::new_a_leg(
            "call-1@10.0.0.1".to_string(),
            "tag-alice".to_string(),
            "z9hG4bK-aleg1".to_string(),
            test_transport(),
        )
    }

    fn make_b_leg(index: usize) -> Leg {
        Leg::new_b_leg(
            format!("b2b-bleg{}", index),
            format!("sb-bleg{}", index),
            format!("sip:bob{}@10.0.0.2", index),
            format!("z9hG4bK-bleg{}", index),
            TransportInfo {
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5060),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
            },
        )
    }

    // --- Leg tests ---

    #[test]
    fn leg_id_is_unique() {
        let id1 = LegId::new();
        let id2 = LegId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn generate_tag_format() {
        let tag = generate_tag();
        assert!(tag.starts_with("sb-"));
        assert_eq!(tag.len(), 15);
    }

    #[test]
    fn generate_call_id_format() {
        let cid = generate_call_id();
        assert!(cid.starts_with("b2b-"));
    }

    #[test]
    fn a_leg_has_inbound_dialog() {
        let leg = make_a_leg();
        assert_eq!(leg.side, LegSide::A);
        assert_eq!(leg.dialog.call_id, "call-1@10.0.0.1");
        assert_eq!(leg.dialog.remote_tag, Some("tag-alice".to_string()));
        assert!(leg.dialog.local_tag.starts_with("sb-"));
        assert_eq!(leg.branch, "z9hG4bK-aleg1");
    }

    #[test]
    fn b_leg_has_outbound_dialog() {
        let leg = make_b_leg(0);
        assert_eq!(leg.side, LegSide::B);
        assert_eq!(leg.dialog.call_id, "b2b-bleg0");
        assert_eq!(leg.dialog.local_tag, "sb-bleg0");
        assert!(leg.dialog.remote_tag.is_none());
        assert_eq!(leg.dialog.target_uri.as_deref(), Some("sip:bob0@10.0.0.2"));
    }

    // --- Dialog rewrite tests ---

    #[test]
    fn dialog_rewrite_swaps_call_id_and_tags() {
        let mut msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=old-tag".to_string())
            .to("<sip:bob@example.com>;tag=bob-tag".to_string())
            .call_id("old-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        Dialog::rewrite_headers(&mut msg, "new-call-id", "old-tag", "new-tag", None);

        assert_eq!(msg.headers.get("Call-ID").unwrap(), "new-call-id");
        assert!(msg.headers.get("From").unwrap().contains("tag=new-tag"));
        assert!(!msg.headers.get("From").unwrap().contains("tag=old-tag"));
        assert!(msg.headers.get("To").unwrap().contains("tag=bob-tag"));
    }

    #[test]
    fn dialog_rewrite_overwrites_to_tag_when_new_to_tag_given() {
        // Reproduces the B2BUA 200 OK forwarding scenario:
        //   B-leg 200 OK has From=siphon-b-tag and To=gateway-tag.
        //   Forwarding to A-leg must rewrite both — From → A-leg's stored
        //   remote tag, AND To → A-leg's local tag (the one the receiving UA
        //   stores as its dialog's remote tag and matches in-dialog requests
        //   against). Without the To rewrite, the BYE we later build with
        //   a_leg.dialog.local_tag in From is rejected with 481.
        let mut msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=b-leg-from-tag".to_string())
            .to("<sip:bob@example.com>;tag=gateway-far-end-tag".to_string())
            .call_id("b-leg-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        Dialog::rewrite_headers(
            &mut msg,
            "a-leg-call-id",
            "b-leg-from-tag",
            "a-leg-remote-tag",
            Some("a-leg-local-tag"),
        );

        assert_eq!(msg.headers.get("Call-ID").unwrap(), "a-leg-call-id");
        let from = msg.headers.get("From").unwrap();
        assert!(from.contains("tag=a-leg-remote-tag"), "From should have A-leg remote tag, got: {from}");
        assert!(!from.contains("tag=b-leg-from-tag"));
        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("tag=a-leg-local-tag"), "To should have A-leg local tag, got: {to}");
        assert!(!to.contains("tag=gateway-far-end-tag"));
    }

    #[test]
    fn dialog_rewrite_skips_to_when_no_existing_tag() {
        // 100 Trying / out-of-dialog responses without an early dialog must
        // not get a synthetic To-tag spliced in: passing Some(...) is a no-op
        // when the inbound message has no To-tag.
        let mut msg = crate::sip::builder::SipMessageBuilder::new()
            .response(100, "Trying".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=from-tag".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        Dialog::rewrite_headers(
            &mut msg,
            "call-id",
            "from-tag",
            "from-tag",
            Some("would-be-synthetic-tag"),
        );

        let to = msg.headers.get("To").unwrap();
        assert!(!to.contains(";tag="), "tagless To must remain tagless, got: {to}");
    }

    #[test]
    fn dialog_rewrite_to_tag_none_leaves_to_alone() {
        // Original out-of-dialog INVITE retry path: caller passes None,
        // To header (whether tagged or not) is left untouched.
        let mut msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@example.com>;tag=from-tag".to_string())
            .to("<sip:bob@example.com>;tag=to-tag-original".to_string())
            .call_id("call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        Dialog::rewrite_headers(&mut msg, "call-id", "from-tag", "from-tag-new", None);

        let to = msg.headers.get("To").unwrap();
        assert!(to.contains("tag=to-tag-original"), "To should be untouched, got: {to}");
    }

    // --- CallActor tests ---

    #[test]
    fn call_actor_create_and_add_b_legs() {
        let mut call = CallActor::new(make_a_leg());
        assert_eq!(call.state, CallState::Calling);
        assert!(call.b_legs.is_empty());

        let idx = call.add_b_leg(make_b_leg(0));
        assert_eq!(idx, 0);
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.b_leg_status[0], BLegStatus::Trying);
    }

    #[test]
    fn call_actor_set_winner() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));

        call.set_winner(1);
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.b_leg_status[1], BLegStatus::Answered);
    }

    #[test]
    fn call_actor_replace_b_leg_supersedes_in_place() {
        // 401/407/422 retry: the retry INVITE supersedes the failed leg at the
        // same index rather than appending a second leg. The parallel vectors
        // stay aligned, the slot's status resets to Trying, its actor handle is
        // cleared, and the old branch is returned for registry re-pointing.
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0)); // CSeq-1 leg, branch z9hG4bK-bleg0
        call.add_b_leg(make_b_leg(1)); // an unrelated fork branch

        // The failed CSeq-1 leg got a final response, and we parked a handle on it.
        call.b_leg_status[0] = BLegStatus::Failed(401);
        let (tx, _rx) = tokio::sync::mpsc::channel::<LegMessage>(1);
        call.b_leg_handles[0] = Some(LegHandle {
            id: call.b_legs[0].id.clone(),
            side: LegSide::B,
            tx,
        });

        // Build the retry leg on a fresh branch and supersede index 0.
        let retry = Leg::new_b_leg(
            "b2b-bleg0".to_string(),
            "sb-bleg0".to_string(),
            "sip:bob0@10.0.0.2".to_string(),
            "z9hG4bK-bleg0-retry".to_string(),
            test_transport(),
        );
        let old_branch = call.replace_b_leg(0, retry);

        assert_eq!(old_branch.as_deref(), Some("z9hG4bK-bleg0"));
        assert_eq!(call.b_legs.len(), 2); // superseded, not appended
        assert_eq!(call.b_legs[0].branch, "z9hG4bK-bleg0-retry"); // live branch
        assert_eq!(call.b_leg_status[0], BLegStatus::Trying); // status reset
        assert!(call.b_leg_handles[0].is_none()); // old actor handle cleared
        // The unrelated fork branch at index 1 is untouched.
        assert_eq!(call.b_legs[1].branch, "z9hG4bK-bleg1");

        // Out-of-range supersede is a no-op returning None.
        assert_eq!(call.replace_b_leg(99, make_b_leg(7)), None);
        assert_eq!(call.b_legs.len(), 2);
    }

    #[test]
    fn call_actor_losers() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        call.add_b_leg(make_b_leg(2));

        // Leg 1 answers
        call.set_winner(1);

        let losers = call.losers(1);
        assert_eq!(losers, vec![0, 2]);
    }

    #[test]
    fn call_actor_should_teardown_on_winner_bye() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        call.set_winner(0);

        // BYE from winner should teardown
        assert!(call.should_teardown_on_b_bye(0));
        // BYE from non-winner should NOT teardown
        assert!(!call.should_teardown_on_b_bye(1));
    }

    #[test]
    fn call_actor_all_failed() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));

        assert!(!call.all_b_legs_settled());

        call.mark_b_leg_failed(0, 486);
        assert!(!call.all_b_legs_settled());

        call.mark_b_leg_failed(1, 503);
        assert!(call.all_b_legs_settled());

        assert_eq!(call.best_error_code(), 503); // 5xx > 4xx
    }

    #[test]
    fn call_actor_remove_b_leg_adjusts_winner() {
        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        call.add_b_leg(make_b_leg(2));
        call.set_winner(2);

        // Remove leg 0 — winner should shift from 2 to 1
        call.remove_b_leg(0);
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.b_legs.len(), 2);
    }

    // --- CallActorStore tests ---

    #[test]
    fn store_create_and_lookup() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());

        assert_eq!(store.count(), 1);
        assert!(store.get_call(&call_id).is_some());
        assert_eq!(store.find_by_sip_call_id("call-1@10.0.0.1"), Some(call_id.clone()));
    }

    #[test]
    fn store_add_b_leg_and_route() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let branch = b_leg.branch.clone();

        assert!(store.add_b_leg(&call_id, b_leg));
        assert_eq!(store.call_id_for_branch(&branch), Some(call_id));
    }

    /// RFC 3261 §14.1 glare detection: take-and-set of the pending_reinvite
    /// flag on the target leg. A second `set_pending_reinvite(_, _, true)`
    /// against the same leg must return the previous `true` so the caller
    /// knows another re-INVITE is already in flight and can reject with 491.
    #[test]
    fn pending_reinvite_flag_tracks_concurrent_reinvites() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));
        store.set_winner(&call_id, 0);

        // First re-INVITE toward B-leg: flag was false, is now true.
        assert!(!store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, true));
        // Second (glare): flag was already true.
        assert!(store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, true));
        // Clear on completion.
        assert!(store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, false));
        // Now a new re-INVITE can start.
        assert!(!store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, true));
    }

    /// RFC 3891 §3 dialog lookup: find a call where one of its legs has
    /// the dialog identifiers (call_id, local_tag, remote_tag) referenced
    /// by a `Replaces` header.
    #[test]
    fn find_call_by_replaces_matches_a_leg() {
        let store = CallActorStore::new();
        let a_leg = make_a_leg();
        let dialog_call_id = a_leg.dialog.call_id.clone();
        let our_tag = a_leg.dialog.local_tag.clone();
        let their_tag = a_leg.dialog.remote_tag.clone().unwrap();
        let call_id = store.create_call(a_leg);

        // Replaces says: "the dialog you (siphon) have where YOU are tagged
        // `our_tag` and the OTHER end is tagged `their_tag`".
        let matched = store.find_call_by_replaces_dialog(&dialog_call_id, &their_tag, &our_tag);
        assert_eq!(matched, Some(call_id));
    }

    #[test]
    fn find_call_by_replaces_no_match_returns_none() {
        let store = CallActorStore::new();
        let _ = store.create_call(make_a_leg());

        let matched = store.find_call_by_replaces_dialog("bogus-call", "x", "y");
        assert_eq!(matched, None);
    }

    #[test]
    fn find_call_by_replaces_wrong_tag_combo() {
        // Right call_id, wrong tag pair → no match (avoid false positives).
        let store = CallActorStore::new();
        let a_leg = make_a_leg();
        let dialog_call_id = a_leg.dialog.call_id.clone();
        let _ = store.create_call(a_leg);

        let matched = store.find_call_by_replaces_dialog(&dialog_call_id, "wrong-from", "wrong-to");
        assert_eq!(matched, None);
    }

    /// RFC 3262 auto-PRACK dedup: each new RSeq returns true once,
    /// retransmits return false so we don't PRACK the same provisional twice.
    #[test]
    fn try_mark_prack_acked_dedupes() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        assert!(store.try_mark_prack_acked(&call_id, 0, 42));
        // Same RSeq again — already PRACKed, returns false.
        assert!(!store.try_mark_prack_acked(&call_id, 0, 42));
        // Earlier RSeq (out-of-order retransmit) — also no PRACK.
        assert!(!store.try_mark_prack_acked(&call_id, 0, 1));
        // Higher RSeq (next reliable 1xx, e.g. 180 after 183) — PRACK it.
        assert!(store.try_mark_prack_acked(&call_id, 0, 43));
    }

    /// 401/407 auth-retry dedup: the first challenge on a B-leg returns true
    /// (drive the retry); every retransmit of that challenge on the same
    /// branch returns false (absorb — ACK only, no second authenticated
    /// INVITE → no 482 merged request). A chained re-challenge arrives on the
    /// retry leg's own branch, which is a distinct B-leg that has not yet been
    /// challenged, so it returns true once on its own.
    #[test]
    fn try_mark_auth_challenged_dedupes_per_leg() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        // First 401 on the original B-leg → retry.
        assert!(store.try_mark_auth_challenged(&call_id, 0));
        // Retransmitted 401 on the same branch → absorbed.
        assert!(!store.try_mark_auth_challenged(&call_id, 0));
        assert!(!store.try_mark_auth_challenged(&call_id, 0));

        // The auth retry adds a new B-leg with a fresh branch. A chained
        // re-challenge (stale nonce) on that leg is a legitimate new challenge.
        store.add_b_leg(&call_id, make_b_leg(1));
        assert!(store.try_mark_auth_challenged(&call_id, 1));
        assert!(!store.try_mark_auth_challenged(&call_id, 1));

        // Out-of-range index returns false (no leg to mark).
        assert!(!store.try_mark_auth_challenged(&call_id, 99));
    }

    /// The per-call credentialed-retry counter backs the dispatcher's auth
    /// retry cap: it starts at 0, increments once per committed retry, and is
    /// readable without mutation. Unknown calls read 0 and increment to 0.
    #[test]
    fn auth_retry_count_increments_and_caps() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());

        assert_eq!(store.auth_retry_count(&call_id), 0);
        assert_eq!(store.incr_auth_retry_count(&call_id), 1);
        assert_eq!(store.incr_auth_retry_count(&call_id), 2);
        // Reading does not mutate.
        assert_eq!(store.auth_retry_count(&call_id), 2);
        assert_eq!(store.incr_auth_retry_count(&call_id), 3);

        // Unknown call: read 0, increment is a no-op returning 0.
        assert_eq!(store.auth_retry_count("nope"), 0);
        assert_eq!(store.incr_auth_retry_count("nope"), 0);
    }

    #[test]
    fn next_b_leg_local_cseq_increments_per_call() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        // B-leg starts at local_cseq = 1 (the INVITE).
        assert_eq!(store.next_b_leg_local_cseq(&call_id, 0), Some(2));
        assert_eq!(store.next_b_leg_local_cseq(&call_id, 0), Some(3));
        assert_eq!(store.next_b_leg_local_cseq(&call_id, 0), Some(4));
        // Out-of-range index returns None.
        assert_eq!(store.next_b_leg_local_cseq(&call_id, 99), None);
    }

    #[test]
    fn pending_reinvite_is_per_leg() {
        // A-leg and B-leg pending flags are independent — a re-INVITE in
        // flight toward the B-leg does NOT block a re-INVITE toward the
        // A-leg.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));
        store.set_winner(&call_id, 0);

        assert!(!store.set_pending_reinvite(&call_id, false, true));
        // The A-leg flag should still be false.
        assert!(!store.set_pending_reinvite(&call_id, true, true));
    }

    #[test]
    fn store_remove_cleans_registry() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let b_leg = make_b_leg(0);
        let b_branch = b_leg.branch.clone();
        let b_cid = b_leg.dialog.call_id.clone();
        store.add_b_leg(&call_id, b_leg);

        store.remove_call(&call_id);

        assert_eq!(store.count(), 0);
        assert!(store.call_id_for_branch(&b_branch).is_none());
        assert!(store.find_by_sip_call_id(&b_cid).is_none());
        assert!(store.find_by_sip_call_id("call-1@10.0.0.1").is_none());
    }

    #[test]
    fn store_replace_b_leg_repoints_registry() {
        // Superseding a B-leg must move the routing registry from the old
        // branch to the retry branch: responses to the retry INVITE route to
        // this call, and the dead pre-auth branch no longer resolves (so a
        // stray retransmit on it can't re-enter the call with a stale leg).
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let original = make_b_leg(0);
        let old_branch = original.branch.clone();
        store.add_b_leg(&call_id, original);
        assert_eq!(store.call_id_for_branch(&old_branch), Some(call_id.clone()));

        let retry = Leg::new_b_leg(
            "b2b-bleg0".to_string(),
            "sb-bleg0".to_string(),
            "sip:bob0@10.0.0.2".to_string(),
            "z9hG4bK-bleg0-retry".to_string(),
            test_transport(),
        );
        assert!(store.replace_b_leg(&call_id, 0, retry));

        // Exactly one leg survives, on the retry branch.
        let call = store.get_call(&call_id).expect("call exists");
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.b_legs[0].branch, "z9hG4bK-bleg0-retry");
        drop(call);

        // Registry now resolves the retry branch, not the dead one.
        assert_eq!(
            store.call_id_for_branch("z9hG4bK-bleg0-retry"),
            Some(call_id.clone())
        );
        assert!(store.call_id_for_branch(&old_branch).is_none());

        // Superseding an unknown call or out-of-range index is a no-op.
        assert!(!store.replace_b_leg("nope", 0, make_b_leg(9)));
        assert!(!store.replace_b_leg(&call_id, 99, make_b_leg(9)));
    }

    #[test]
    fn store_remove_call_after_cancel_zombifies_pending_legs() {
        // A CANCELled call's still-pending B-leg (INVITE on the wire, status
        // Trying) must survive teardown as a zombie-cancelled entry so a 2xx
        // that raced the CANCEL can be ACKed + BYEd. A leg whose INVITE never
        // went out (no stash) must not.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());

        let mut sent_leg = make_b_leg(0);
        let sent_cid = sent_leg.dialog.call_id.clone();
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("10.0.0.2".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-b0".to_string())
            .from("<sip:alice@10.0.0.1>;tag=a".to_string())
            .to("<sip:bob@10.0.0.2>".to_string())
            .call_id(sent_cid.clone())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        sent_leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
        store.add_b_leg(&call_id, sent_leg);

        // A second B-leg whose INVITE never went on the wire (no stash).
        let unsent_leg = make_b_leg(1);
        let unsent_cid = unsent_leg.dialog.call_id.clone();
        store.add_b_leg(&call_id, unsent_leg);

        let captured = store.remove_call_after_cancel(&call_id);
        assert!(captured, "the sent, still-pending leg should be zombified");
        assert_eq!(store.count(), 0, "the call itself is removed");

        // The sent leg resolves as a zombie; the unsent one does not.
        let (leg, first) = store
            .zombie_cancelled_for_2xx(&sent_cid)
            .expect("zombie present for the sent leg");
        assert!(first, "the first racing 2xx triggers ACK + BYE");
        assert_eq!(leg.dialog.call_id, sent_cid);
        assert!(store.zombie_cancelled_for_2xx(&unsent_cid).is_none());

        // A retransmitted 2xx for the same Call-ID re-ACKs only (no second BYE).
        let (_leg, second) = store
            .zombie_cancelled_for_2xx(&sent_cid)
            .expect("entry stays until the 32s cleanup");
        assert!(!second, "a retransmit must not trigger a second BYE");
    }

    #[test]
    fn store_sweep_stale() {
        let store = CallActorStore::new();
        store.create_call(make_a_leg());
        assert_eq!(store.sweep_stale(std::time::Duration::from_secs(60)), 0);
        assert_eq!(store.sweep_stale(std::time::Duration::ZERO), 1);
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn take_timed_out_calls_only_unanswered_past_deadline() {
        // The answer-timeout sweep must select only calls that are still
        // un-answered AND past their deadline — never an answered call, a call
        // whose deadline is in the future, or one with no deadline. And it must
        // not remove anything (the dispatcher runs the teardown).
        let store = CallActorStore::new();
        let now = std::time::Instant::now();
        let past = now - std::time::Duration::from_secs(1);
        let future = now + std::time::Duration::from_secs(60);

        // Un-answered (Calling), deadline already passed → timed out.
        let stuck = store.create_call(make_a_leg());
        store.set_answer_deadline(&stuck, past);

        // Un-answered, deadline still in the future → not yet.
        let waiting = store.create_call(make_a_leg());
        store.set_answer_deadline(&waiting, future);

        // Answered, deadline passed → never (it answered; lives until BYE).
        let answered = store.create_call(make_a_leg());
        store.set_answer_deadline(&answered, past);
        store.add_b_leg(&answered, make_b_leg(0));
        store.set_winner(&answered, 0);

        // No deadline → only the 24h orphan backstop applies.
        let no_deadline = store.create_call(make_a_leg());

        let timed_out = store.take_timed_out_calls(now);
        assert_eq!(timed_out, vec![stuck.clone()]);
        // Nothing was removed.
        assert_eq!(store.count(), 4);
        let _ = (waiting, answered, no_deadline);
    }

    // --- LegRegistry tests ---

    #[test]
    fn registry_basic() {
        let reg = LegRegistry::new();
        reg.register_call_id("call-1@host", "internal-1");
        reg.register_branch("z9hG4bK-test", "internal-1");

        assert_eq!(reg.lookup_call_id("call-1@host"), Some("internal-1".to_string()));
        assert_eq!(reg.lookup_branch("z9hG4bK-test"), Some("internal-1".to_string()));
        assert!(reg.lookup_call_id("nonexistent").is_none());

        reg.remove_call_id("call-1@host");
        assert!(reg.lookup_call_id("call-1@host").is_none());
    }

    // --- Extract tag test ---

    #[test]
    fn extract_to_tag_from_response() {
        let msg = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("test@host".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        assert_eq!(extract_to_tag(&msg), Some("xyz".to_string()));
    }

    // --- B-leg handle tracking ---

    #[test]
    fn call_actor_b_leg_handles_parallel_with_b_legs() {
        let mut call = CallActor::new(make_a_leg());
        assert!(call.b_leg_handles.is_empty());

        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));
        assert_eq!(call.b_leg_handles.len(), 2);
        assert!(call.b_leg_handles[0].is_none());
        assert!(call.b_leg_handles[1].is_none());

        // Set a handle for leg 1
        let (call_tx, _call_rx) = tokio::sync::mpsc::channel(16);
        let (_, handle) = LegActor::new(make_b_leg(1), call_tx);
        call.set_b_leg_handle(1, handle);
        assert!(call.b_leg_handles[0].is_none());
        assert!(call.b_leg_handles[1].is_some());

        // Remove leg 0 — handle vector stays in sync
        call.remove_b_leg(0);
        assert_eq!(call.b_leg_handles.len(), 1);
        assert!(call.b_leg_handles[0].is_some());
    }

    // --- LegActor async tests ---

    #[tokio::test]
    async fn leg_actor_lifecycle() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Terminated { leg_id: id } => assert_eq!(id, leg_id),
            _ => panic!("expected Terminated event"),
        }
    }

    #[tokio::test]
    async fn leg_actor_classifies_200_ok_as_answered() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        // Send a 200 OK response to the actor
        let response = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        }).await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Answered { leg_id: id, .. } => assert_eq!(id, leg_id),
            other => panic!("expected Answered, got {:?}", other),
        }

        // Shut down
        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_classifies_486_as_failed() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let response = crate::sip::builder::SipMessageBuilder::new()
            .response(486, "Busy Here".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        }).await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Failed { leg_id: id, status_code, .. } => {
                assert_eq!(id, leg_id);
                assert_eq!(status_code, 486);
            }
            other => panic!("expected Failed, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_classifies_180_as_provisional() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let response = crate::sip::builder::SipMessageBuilder::new()
            .response(180, "Ringing".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        }).await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Provisional { leg_id: id, status_code, .. } => {
                assert_eq!(id, leg_id);
                assert_eq!(status_code, 180);
            }
            other => panic!("expected Provisional, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_cancel_stops_loop() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        handle.tx.send(LegMessage::Cancel).await.unwrap();
        join.await.unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Terminated { leg_id: id } => assert_eq!(id, leg_id),
            other => panic!("expected Terminated, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn leg_actor_classifies_bye_request() {
        use crate::sip::message::Method;

        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let bye = crate::sip::builder::SipMessageBuilder::new()
            .request(Method::Bye, crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060))
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("2 BYE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: bye,
            source: test_transport(),
        }).await.unwrap();

        let event = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            call_rx.recv(),
        ).await.unwrap().unwrap();
        match event {
            CallEvent::Bye { leg_id: id, from_side, .. } => {
                assert_eq!(id, leg_id);
                assert_eq!(from_side, LegSide::B);
            }
            other => panic!("expected Bye, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_classifies_reinvite_request() {
        use crate::sip::message::Method;

        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let reinvite = crate::sip::builder::SipMessageBuilder::new()
            .request(Method::Invite, crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060))
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-reinv".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("2 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: reinvite,
            source: test_transport(),
        }).await.unwrap();

        let event = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            call_rx.recv(),
        ).await.unwrap().unwrap();
        match event {
            CallEvent::ReInvite { leg_id: id, .. } => assert_eq!(id, leg_id),
            other => panic!("expected ReInvite, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    // --- rewrite_uri_host tests ---

    #[test]
    fn rewrite_uri_host_standard_from() {
        let from = "<sip:alice@10.0.0.1:5060>;tag=abc123";
        let result = rewrite_uri_host(from, "203.0.113.1");
        assert_eq!(result, "<sip:alice@203.0.113.1:5060>;tag=abc123");
    }

    #[test]
    fn rewrite_uri_host_no_port() {
        let from = "<sip:alice@10.0.0.1>;tag=abc123";
        let result = rewrite_uri_host(from, "sbc.example.com");
        assert_eq!(result, "<sip:alice@sbc.example.com>;tag=abc123");
    }

    #[test]
    fn rewrite_uri_host_with_params() {
        let from = "<sip:alice@10.0.0.1;transport=udp>;tag=abc123";
        let result = rewrite_uri_host(from, "203.0.113.1");
        assert_eq!(result, "<sip:alice@203.0.113.1;transport=udp>;tag=abc123");
    }

    #[test]
    fn rewrite_uri_host_display_name() {
        let from = "\"Alice\" <sip:alice@192.168.1.1:5060>;tag=xyz";
        let result = rewrite_uri_host(from, "pub.example.com");
        assert_eq!(result, "\"Alice\" <sip:alice@pub.example.com:5060>;tag=xyz");
    }

    #[test]
    fn rewrite_uri_host_no_at_sign() {
        let from = "<sip:192.168.1.1:5060>;tag=abc";
        let result = rewrite_uri_host(from, "203.0.113.1");
        // No @ sign — should return unchanged
        assert_eq!(result, from);
    }

    #[test]
    fn rewrite_uri_host_pai_with_display() {
        let pai = "\"Outbound Call\" <sip:W5LeMb7O@172.31.47.238>";
        let result = rewrite_uri_host(pai, "63.176.27.178");
        assert_eq!(result, "\"Outbound Call\" <sip:W5LeMb7O@63.176.27.178>");
    }

    // --- ensure_tag tests ---

    #[test]
    fn ensure_tag_appends_when_missing() {
        let to = "<sip:bob@example.com:5060>";
        assert_eq!(
            ensure_tag(to, Some("xyz123")),
            "<sip:bob@example.com:5060>;tag=xyz123"
        );
    }

    #[test]
    fn ensure_tag_idempotent_when_already_tagged() {
        let to = "<sip:bob@example.com>;tag=existing";
        assert_eq!(ensure_tag(to, Some("xyz123")), to);
    }

    #[test]
    fn ensure_tag_no_op_on_none() {
        let to = "<sip:bob@example.com>";
        assert_eq!(ensure_tag(to, None), to);
    }

    #[test]
    fn ensure_tag_no_op_on_empty() {
        let to = "<sip:bob@example.com>";
        assert_eq!(ensure_tag(to, Some("")), to);
    }

    #[test]
    fn ensure_tag_trims_trailing_whitespace_before_appending() {
        let to = "<sip:bob@example.com>  ";
        assert_eq!(
            ensure_tag(to, Some("abc")),
            "<sip:bob@example.com>;tag=abc"
        );
    }

    #[test]
    fn ensure_tag_with_display_name() {
        let to = "\"Bob\" <sip:bob@example.com>";
        assert_eq!(
            ensure_tag(to, Some("xyz")),
            "\"Bob\" <sip:bob@example.com>;tag=xyz"
        );
    }

    #[tokio::test]
    async fn leg_actor_classifies_refer_request() {
        use crate::sip::message::Method;

        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);
        let leg_id = leg.id.clone();

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        let refer = crate::sip::builder::SipMessageBuilder::new()
            .request(Method::Refer, crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060))
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-refer".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("3 REFER".to_string())
            .header("Refer-To", "<sip:carol@chicago.com>".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: refer,
            source: test_transport(),
        }).await.unwrap();

        let event = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            call_rx.recv(),
        ).await.unwrap().unwrap();
        match event {
            CallEvent::Refer { leg_id: id, .. } => assert_eq!(id, leg_id),
            other => panic!("expected Refer, got {:?}", other),
        }

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn leg_actor_ignores_unknown_request() {
        use crate::sip::message::Method;

        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
        let leg = make_b_leg(0);

        let (actor, handle) = LegActor::new(leg, call_tx);
        let join = tokio::spawn(actor.run());

        // OPTIONS is not classified by the actor — no event emitted
        let options = crate::sip::builder::SipMessageBuilder::new()
            .request(Method::Options, crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060))
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-opts".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("4 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle.tx.send(LegMessage::SipInbound {
            message: options,
            source: test_transport(),
        }).await.unwrap();

        // Should timeout — no event expected
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            call_rx.recv(),
        ).await;
        assert!(result.is_err(), "expected timeout, got event");

        handle.tx.send(LegMessage::Shutdown).await.unwrap();
        join.await.unwrap();
    }

    #[tokio::test]
    async fn forking_multiple_actors_share_event_channel() {
        let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);

        // Spawn 3 B-leg actors sharing the same event_tx
        let mut handles = Vec::new();
        let mut leg_ids = Vec::new();
        let mut joins = Vec::new();
        for i in 0..3 {
            let leg = make_b_leg(i);
            leg_ids.push(leg.id.clone());
            let (actor, handle) = LegActor::new(leg, call_tx.clone());
            joins.push(tokio::spawn(actor.run()));
            handles.push(handle);
        }

        // Send different responses to each actor
        // Leg 0: 180 Ringing
        let ringing = crate::sip::builder::SipMessageBuilder::new()
            .response(180, "Ringing".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f0".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=b0".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build().unwrap();
        handles[0].tx.send(LegMessage::SipInbound {
            message: ringing, source: test_transport(),
        }).await.unwrap();

        // Leg 1: 486 Busy
        let busy = crate::sip::builder::SipMessageBuilder::new()
            .response(486, "Busy Here".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f1".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=b1".to_string())
            .call_id("b2b-bleg1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build().unwrap();
        handles[1].tx.send(LegMessage::SipInbound {
            message: busy, source: test_transport(),
        }).await.unwrap();

        // Leg 2: 200 OK
        let ok = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f2".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=b2".to_string())
            .call_id("b2b-bleg2".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build().unwrap();
        handles[2].tx.send(LegMessage::SipInbound {
            message: ok, source: test_transport(),
        }).await.unwrap();

        // Collect all 3 events — order may vary
        let mut events = Vec::new();
        for _ in 0..3 {
            let event = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                call_rx.recv(),
            ).await.unwrap().unwrap();
            events.push(event);
        }

        // Verify all 3 leg_ids are present
        let event_leg_ids: std::collections::HashSet<String> = events.iter().map(|e| match e {
            CallEvent::Provisional { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Answered { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Failed { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Terminated { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Bye { leg_id, .. } => leg_id.0.clone(),
            CallEvent::ReInvite { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Refer { leg_id, .. } => leg_id.0.clone(),
        }).collect();

        for id in &leg_ids {
            assert!(event_leg_ids.contains(&id.0), "missing event for leg {}", id);
        }

        // Verify event types
        assert!(events.iter().any(|e| matches!(e, CallEvent::Provisional { status_code: 180, .. })));
        assert!(events.iter().any(|e| matches!(e, CallEvent::Failed { status_code: 486, .. })));
        assert!(events.iter().any(|e| matches!(e, CallEvent::Answered { .. })));

        // Shutdown all
        for handle in &handles {
            let _ = handle.tx.send(LegMessage::Shutdown).await;
        }
        for join in joins {
            let _ = join.await;
        }
    }

    #[tokio::test]
    async fn shutdown_actors_terminates_running_tasks() {
        let (call_tx, _call_rx) = tokio::sync::mpsc::channel(16);

        let mut call = CallActor::new(make_a_leg());
        call.add_b_leg(make_b_leg(0));
        call.add_b_leg(make_b_leg(1));

        let mut joins = Vec::new();
        for i in 0..2 {
            let leg = make_b_leg(i);
            let (actor, handle) = LegActor::new(leg, call_tx.clone());
            joins.push(tokio::spawn(actor.run()));
            call.set_b_leg_handle(i, handle);
        }

        // All actors should be running
        for join in &joins {
            assert!(!join.is_finished());
        }

        // shutdown_actors sends Shutdown to all
        call.shutdown_actors();

        // All tasks should complete within timeout
        for join in joins {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                join,
            ).await.expect("actor did not terminate").unwrap();
        }
    }
}
