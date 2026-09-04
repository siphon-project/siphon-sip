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

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{debug, warn};

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
    /// siphon's owned SDP `o=` session-id for SDP it emits toward this leg's
    /// peer (RFC 4566 §5.2). Stable for the dialog's life — generated once at
    /// creation — so every offer/answer siphon sends this peer shares one
    /// session identity (RFC 3264 §8).
    pub sdp_session_id: u64,
    /// Monotonic SDP `o=` version for SDP siphon emits toward this leg's peer.
    /// Incremented on every emit so a re-INVITE that changes the media (e.g. a
    /// transfer re-anchor) presents a strictly greater version than the last
    /// SDP the peer saw — otherwise a strict RFC 3264 §8 answerer may treat the
    /// changed offer as unchanged and skip re-answering.
    pub sdp_version: u64,
}

/// Generate a fresh SDP `o=` session-id (RFC 4566 §5.2 — a numeric identifier).
pub fn generate_sdp_session_id() -> u64 {
    uuid::Uuid::new_v4().as_u128() as u64
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
            sdp_session_id: generate_sdp_session_id(),
            sdp_version: 0,
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
            sdp_session_id: generate_sdp_session_id(),
            sdp_version: 0,
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

        if let Some(from) = message
            .headers
            .get("From")
            .or_else(|| message.headers.get("f"))
        {
            if from.contains(&old_pattern) {
                let new_from = from.replace(&old_pattern, &new_pattern);
                message.headers.set("From", new_from);
            }
        }
        if let Some(to) = message
            .headers
            .get("To")
            .or_else(|| message.headers.get("t"))
        {
            if to.contains(&old_pattern) {
                let new_to = to.replace(&old_pattern, &new_pattern);
                message.headers.set("To", new_to);
            }
        }

        if let Some(new_tag) = new_to_tag {
            if let Some(to) = message
                .headers
                .get("To")
                .or_else(|| message.headers.get("t"))
            {
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
        let host_end = after_at.find(['>', ';', ':']).unwrap_or(after_at.len());
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

/// Rewrite the whole `host[:port]` authority of a SIP URI in a From/To header
/// value.
///
/// Unlike [`rewrite_uri_host`] — which replaces only the host token and leaves
/// any existing `:port` in place — this replaces the entire `host[:port]`
/// authority with `new_authority`. Use it when substituting a dial-target
/// authority that itself carries a port (e.g. topology-hiding the B-leg To to
/// the next-hop): replacing host-only there would splice the new `host:port` in
/// front of the retained old port and emit a malformed `host:newport:oldport`
/// (double port), which some SBCs reject as `400 Wrong URI`.
pub fn rewrite_uri_authority(header_value: &str, new_authority: &str) -> String {
    if let Some(at_pos) = header_value.find('@') {
        let after_at = &header_value[at_pos + 1..];
        // Split only on the URI-param / bracket terminators, NOT on ':', so the
        // original port is consumed along with the host.
        let authority_end = after_at.find(['>', ';']).unwrap_or(after_at.len());
        let end_pos = at_pos + 1 + authority_end;
        format!(
            "{}{}{}",
            &header_value[..at_pos + 1],
            new_authority,
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
    /// Local listener socket this leg is anchored on, when known. Set for the
    /// A-leg to the address the inbound INVITE arrived on so siphon-originated
    /// requests to this leg (framework BYE, forwarded in-dialog requests) and the
    /// advertised Via/Contact use the *arrival* listener, not the first-configured
    /// one — the multi-homed-host source-port parity the response paths already
    /// enforce. `None` for outbound B-legs (source socket chosen by the send path /
    /// `send_socket=`) and in tests; consumers fall back to the default listener,
    /// so on a single-listener host this is a no-op.
    pub local_addr: Option<SocketAddr>,
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
    /// Stored From header of the request that created this (pseudo-)leg, kept
    /// verbatim so a response relayed back to the originator echoes it exactly
    /// (RFC 3261 §8.2.6.2). Used by the transparent REFER/NOTIFY relay: the
    /// dialog-derived URI can differ from what the peer actually sent (e.g. a
    /// `:5060` the peer omitted), so reconstructing From/To from dialog state
    /// would break the verbatim-echo MUST. `None` for legs that don't need it.
    pub stored_from: Option<String>,
    /// Stored To header of the request that created this (pseudo-)leg. See
    /// [`Leg::stored_from`].
    pub stored_to: Option<String>,
    /// This leg's own most-recent endpoint SDP, stored **raw** (the peer's true
    /// media address, before any rtpengine rewrite or topology masking). Kept so
    /// a siphon-terminated transfer can offer the *surviving* leg's real media
    /// to the transfer target (or feed it to an rtpengine re-anchor) instead of
    /// the referrer's SDP. `None` until the leg has negotiated a body.
    pub last_sdp: Option<Vec<u8>>,
    /// Whether the initial INVITE on this leg has been ACKed.
    pub initial_acked: bool,
    /// Whether a re-INVITE toward this leg is currently in flight
    /// (awaiting a final response). Used by glare detection
    /// (RFC 3261 §14.1): if a new re-INVITE arrives while one is
    /// already pending toward the same leg we respond 491 Request
    /// Pending rather than forward a second concurrent offer/answer.
    pub pending_reinvite: bool,
    /// Highest RSeq we've already PRACKed for each early dialog on this leg
    /// (RFC 3262 auto-PRACK), keyed by the early dialog's remote To-tag.
    /// Reliable 1xx responses retransmit until PRACKed — without this guard we
    /// would emit a fresh PRACK for every retransmit, racking up CSeq numbers
    /// and confusing the peer. Keyed per To-tag (not a single value) because a
    /// downstream fork produces several early dialogs on this one INVITE
    /// branch, each with an INDEPENDENT RSeq space (RFC 3262 §3) that commonly
    /// restarts at 1 — a single monotonic slot would swallow the second
    /// dialog's low RSeqs.
    pub prack_acked_rseq: HashMap<String, u32>,
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
            stored_from: None,
            stored_to: None,
            last_sdp: None,
            initial_acked: false,
            pending_reinvite: false,
            prack_acked_rseq: HashMap::new(),
            b_leg_invite: None,
            pending_cancel: false,
            auth_challenged: false,
        }
    }

    /// Create the single leg of a call **siphon itself placed** (`originate`).
    ///
    /// Siphon is the UAC on this leg — there is no inbound INVITE and no caller
    /// to bridge to — so it carries an *outbound* dialog ([`Dialog::new_outbound`])
    /// while still occupying the A-leg slot: the A-leg is "the leg the call
    /// starts from", and every teardown / in-dialog path
    /// ([`crate::b2bua::actor::CallActor::request_direction`], the framework BYE
    /// builder, the media safety-net) keys on it. `local_tag` is our From-tag
    /// (RFC 3261 §8.1.1.3) and `branch` the INVITE's own Via branch.
    pub fn new_originating_leg(
        call_id: String,
        local_tag: String,
        target_uri: String,
        branch: String,
        transport: TransportInfo,
    ) -> Self {
        Self {
            side: LegSide::A,
            ..Self::new_b_leg(call_id, local_tag, target_uri, branch, transport)
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
            stored_from: None,
            stored_to: None,
            last_sdp: None,
            initial_acked: false,
            pending_reinvite: false,
            prack_acked_rseq: HashMap::new(),
            b_leg_invite: None,
            pending_cancel: false,
            auth_challenged: false,
        }
    }

    /// True for the re-INVITE/UPDATE/REFER/NOTIFY response-tracking pseudo-legs
    /// the dispatcher inserts as B-legs. Their `target_uri` is a direction
    /// marker (`reinvite:`/`update:`/`refer:`/`notify:`/`refer_out:`/`…_done:`)
    /// and they deliberately reuse another leg's Call-ID for response routing,
    /// so they must be excluded from dialog-identity direction matching.
    pub fn is_tracking_leg(&self) -> bool {
        self.dialog.target_uri.as_deref().is_some_and(|target| {
            target.starts_with("reinvite:")
                || target.starts_with("reinvite_done:")
                || target.starts_with("update:")
                || target.starts_with("update_done:")
                || target.starts_with("refer:")
                || target.starts_with("refer_done:")
                || target.starts_with("notify:")
                || target.starts_with("notify_done:")
                || target.starts_with("refer_out:")
                || target.starts_with("refer_out_done:")
        })
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
    /// Via branch → the siphon-originated REFER that branch belongs to.
    ///
    /// Kept apart from [`Self::by_branch`], which maps a branch to a *leg* whose
    /// responses run the INVITE/B-leg machinery in `handle_b2bua_response`. An
    /// in-dialog REFER siphon originates is a non-INVITE transaction on an
    /// existing leg, so it needs the call for a credentialed retry but none of
    /// that machinery. Registering it in `by_branch` would send its 401 down the
    /// B-leg path, which ACKs (wrong for a non-INVITE, RFC 3261 §17.1.2) and
    /// reasons about legs that do not exist on a single-leg call.
    originated_refers: DashMap<String, OriginatedRefer>,
    /// Via branch → internal call ID for an INVITE **siphon originated**
    /// (`originate`).
    ///
    /// Kept apart from [`Self::by_branch`] for the same reason
    /// [`Self::originated_refers`] is: a response matched there runs
    /// `handle_b2bua_response`, which relays the far end's provisionals/finals
    /// to an A-leg and reasons about B-legs. An originated call *is* the A-leg
    /// and has no B-leg, so relaying its own 180 back at the peer we are calling
    /// is exactly wrong. This index gives the response path a first, explicit
    /// hook (checked before the leg-branch lookup) into the UAC-side handler.
    originated_calls: DashMap<String, String>,
}

/// A REFER siphon sent on one of its own legs, awaiting a response.
///
/// Tracked so a 401/407 can be retried with the call's credentials
/// (`call.set_credentials()`); without this the challenge matches no branch at
/// all and the transfer fails silently.
#[derive(Debug, Clone)]
pub struct OriginatedRefer {
    /// Internal call id the REFER was sent on.
    pub call_id: String,
    /// Which leg it went out on (`true` = A-leg, the connected caller).
    pub on_a_leg: bool,
    /// Request-URI the REFER was addressed to — the digest `uri` parameter of
    /// any credentialed retry must match it (RFC 7616 §3.4.6).
    pub target_uri: String,
    /// The `Refer-To` this REFER carried, so a retry reproduces it exactly.
    pub refer_to: crate::sip::headers::refer::ReferTo,
    /// Credentialed retries already sent for this REFER, capped so a peer that
    /// challenges unconditionally cannot drive an unbounded loop.
    pub auth_retries: u32,
}

impl LegRegistry {
    pub fn new() -> Self {
        Self {
            by_call_id: DashMap::new(),
            by_branch: DashMap::new(),
            originated_refers: DashMap::new(),
            originated_calls: DashMap::new(),
        }
    }

    /// Record a siphon-originated INVITE branch so its responses reach the
    /// UAC-side handler instead of the B-leg relay machinery.
    pub fn register_originated_call(&self, branch: &str, internal_id: &str) {
        self.originated_calls
            .insert(branch.to_string(), internal_id.to_string());
    }

    /// The internal call id of the originate this branch belongs to, if any.
    pub fn lookup_originated_call(&self, branch: &str) -> Option<String> {
        self.originated_calls.get(branch).map(|entry| entry.clone())
    }

    /// Drop the originate branch index entry of a call that is gone.
    pub fn clear_originated_calls(&self, internal_id: &str) {
        self.originated_calls
            .retain(|_, id| id.as_str() != internal_id);
    }

    /// Number of tracked originate branches (leak-test accessor).
    #[cfg(test)]
    pub fn originated_call_count(&self) -> usize {
        self.originated_calls.len()
    }

    /// Record a siphon-originated REFER so its response can be matched.
    pub fn register_originated_refer(&self, branch: &str, refer: OriginatedRefer) {
        self.originated_refers.insert(branch.to_string(), refer);
    }

    /// Look up (without removing) the originated REFER a branch belongs to.
    pub fn lookup_originated_refer(&self, branch: &str) -> Option<OriginatedRefer> {
        self.originated_refers
            .get(branch)
            .map(|entry| entry.clone())
    }

    /// Remove and return the originated REFER a branch belongs to — the final
    /// response for a non-INVITE transaction ends it, so the entry goes with it.
    pub fn take_originated_refer(&self, branch: &str) -> Option<OriginatedRefer> {
        self.originated_refers
            .remove(branch)
            .map(|(_, refer)| refer)
    }

    /// Drop every originated REFER belonging to a call.
    pub fn clear_originated_refers(&self, internal_id: &str) {
        self.originated_refers
            .retain(|_, refer| refer.call_id.as_str() != internal_id);
    }

    /// Register a SIP Call-ID → internal call ID mapping.
    pub fn register_call_id(&self, sip_call_id: &str, internal_id: &str) {
        self.by_call_id
            .insert(sip_call_id.to_string(), internal_id.to_string());
    }

    /// Register a Via branch → internal call ID mapping.
    pub fn register_branch(&self, branch: &str, internal_id: &str) {
        self.by_branch
            .insert(branch.to_string(), internal_id.to_string());
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
        // ...including any REFER siphon originated on it and is still awaiting a
        // response. A call that is gone cannot be transferred, and leaving the
        // entry would leak one per abandoned transfer.
        self.originated_refers
            .retain(|_, refer| refer.call_id.as_str() != internal_id);
        // ...and the originate branch, for the same reason: one entry per placed
        // call would otherwise never drain.
        self.originated_calls
            .retain(|_, id| id.as_str() != internal_id);
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

/// A REFER subscription (RFC 3515) that siphon owns for a transfer in progress
/// on a B2BUA call.
///
/// Two roles:
/// - **notifier** (`siphon_notifies == true`) — the siphon-terminated inbound
///   path: a UA sent siphon a REFER, siphon answered `202`, and now sends the
///   `message/sipfrag` NOTIFY progress to that referrer as the new leg it dialed
///   makes progress.
/// - **subscriber** (`siphon_notifies == false`) — the siphon-originated path
///   (`call.refer()`): siphon sent a REFER to a connected UA and receives that
///   UA's sipfrag NOTIFYs, which it `200 OK`s and reads for teardown.
///
/// The transparent-forward path owns no subscription — it bridges the peers'
/// own NOTIFYs across the two dialogs.
#[derive(Debug, Clone)]
pub struct ReferSubscription {
    /// Which leg of this call carries the subscription dialog (the leg the REFER
    /// was received on for a terminated transfer, or sent on for an originated
    /// one).
    pub on_a_leg: bool,
    /// True when siphon is the notifier, false when siphon is the subscriber.
    pub siphon_notifies: bool,
    /// The subscription `id` token — the CSeq number of the REFER that created
    /// it (RFC 3515 §2.4.4) — surfaced as `Event: refer;id=<n>` to disambiguate
    /// concurrent transfers on one dialog.
    pub event_id: u32,
    /// Next CSeq for a siphon-originated NOTIFY on this subscription (notifier
    /// role only).
    pub notify_cseq: u32,
    /// Current transfer progress (drives the sipfrag body and teardown).
    pub state: super::transfer::TransferState,
    /// For a siphon-terminated inbound transfer: the dialog Call-ID of the leg
    /// siphon dialed to the transfer target. The response path matches an
    /// answering b_leg against this exact Call-ID (not just "a non-winner leg")
    /// so an unrelated leg dialed while a transfer is pending can't be mistaken
    /// for the transfer target. `None` for the subscriber (outbound) role.
    pub target_leg_call_id: Option<String>,
    /// True once the referrer's dialog ended while this transfer was still in
    /// flight — the referrer sent a BYE after siphon accepted the REFER but
    /// before the dialed target resolved.
    ///
    /// RFC 3515 §2.4.4: the implicit refer subscription lives in the dialog the
    /// REFER arrived on, so once that dialog ends no further NOTIFY can be
    /// delivered (a late one draws a 481) and the referrer needs no BYE at
    /// completion — it already left. The transfer itself continues: RFC 5589 §7
    /// has the transferor free to end its dialog as soon as the REFER is
    /// accepted, and the surviving party ↔ target call is what the transfer
    /// exists to create. Notifier (siphon-terminated) role only.
    pub referrer_gone: bool,
    /// Media profile chosen for the pairing this transfer creates
    /// (`accept_refer(profile=…)`). `None` inherits the profile the call was
    /// anchored with — correct only when that profile is symmetric, see
    /// [`ProfileEntry::is_direction_bound`](crate::rtpengine::ProfileEntry::is_direction_bound).
    pub media_profile: Option<String>,
}

/// One end of a dialog, in the shape `Replaces` (RFC 3891) names it.
///
/// Produced by [`CallActorStore::replaces_as_seen_by_peer`] when an attended
/// transfer's `Replaces` has to be rewritten from the referrer's view of a
/// dialog to the transfer target's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacesDialog {
    /// Call-ID of the dialog, as the far party knows it.
    pub call_id: String,
    /// The `from-tag` parameter — siphon's local tag on the leg facing that party.
    pub from_tag: String,
    /// The `to-tag` parameter — that party's own tag.
    pub to_tag: String,
}

/// Which call, and which of its legs, an inbound `Replaces` (RFC 3891) named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacesMatch {
    /// Internal id of the call holding the named dialog.
    pub call_id: String,
    /// True when the named dialog is that call's A-leg; false for its winning
    /// B-leg. Determines which party survives the takeover — the *other* one.
    pub on_a_leg: bool,
}

/// An inbound INVITE carrying a `Replaces` (RFC 3891) that matched a dialog this
/// node hosts, recorded on the new call while the INVITE is still being admitted.
///
/// The takeover is deliberately NOT performed at header-parse time. RFC 3891 §5
/// warns that a party who learns a dialog's identifiers can use `Replaces` to
/// hijack the call, so the request has to clear the same admission the script
/// applies to any other INVITE — `auth.require_proxy_digest()` in
/// `@b2bua.on_invite` — before siphon acts on it. This carries the resolved
/// match across that gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReplaces {
    /// The call whose dialog is being taken over.
    pub replaced_call_id: String,
    /// Which leg of that call the header named.
    pub replaced_on_a_leg: bool,
    /// The `early-only` flag (RFC 3891 §3) as it arrived.
    pub early_only: bool,
}

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
/// Sequential-failover state for a call driven by `call.route(...)` (LCR) or
/// `call.fork(strategy="sequential")`.
///
/// Carriers are tried one at a time in order: [`active`](Self::active) is the
/// attempt currently in flight (or the winner after a 2xx), [`pending`](Self::pending)
/// holds the not-yet-tried carriers (front = next), and [`attempts`](Self::attempts)
/// records every carrier that failed. When `None` on a [`CallActor`], the call is a
/// plain single dial or a parallel fork (no failover). Each attempt is a fresh
/// B-leg dialog (`b2bua_send_b_leg_invite` mints a new Call-ID/From-tag/CSeq per
/// call), so no carrier ever sees a reused Call-ID.
#[derive(Debug, Default)]
pub struct RouteSequenceState {
    /// Carriers still to try, front = next attempt.
    pub pending: std::collections::VecDeque<crate::lcr::Route>,
    /// The carrier currently in flight — becomes the winner on a 2xx answer.
    /// Surfaced to scripts as `call.active_route` for CDR/charging.
    pub active: Option<crate::lcr::Route>,
    /// Every failed attempt, in the order they were tried.
    ///
    /// This used to be a single `best_error: Option<u16>`, which is all the
    /// A-leg needs (the code sent once every carrier is exhausted) and nothing
    /// an operator needs: a call that burned a carrier on its way to answering
    /// recorded that nowhere, so a failing carrier could not be alerted on,
    /// trended, or taken to the carrier. The best error is now derived from
    /// this — see [`CallActor::best_route_error`].
    pub attempts: Vec<RouteAttempt>,
    /// When the in-flight attempt was dialled, for its elapsed time.
    pub active_since: Option<std::time::Instant>,
    /// Call-level send-socket egress pin applied to every attempt.
    pub send_socket: Option<String>,
    /// Ring timeout (seconds) for a route that omits its own `timeout_secs`.
    pub default_timeout: u32,
}

/// One failed carrier attempt in a sequential failover sequence.
///
/// Surfaced to scripts as `call.route_attempts`, to `@b2bua.on_route_failure`,
/// and onto the CDR as `lcr_attempts`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAttempt {
    /// The carrier that was tried (`Route::carrier_id`).
    pub carrier_id: String,
    /// Its final status. A ring timeout is recorded as `408`, the code the
    /// attempt effectively ended on.
    pub status: u16,
    /// How long the attempt was in flight, in milliseconds.
    pub elapsed_ms: u64,
}

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
    /// Local (listener) address the A-leg INVITE arrived on. Captured at INVITE
    /// so an imperative `call.answer()` / `call.progress()` sends the UAS
    /// response back out the same listener (source-socket parity with the
    /// inbound-driven send path on a multi-homed host).
    pub a_leg_local_addr: Option<std::net::SocketAddr>,
    /// RFC 4028 session timer state (set after 200 OK negotiation).
    pub session_timer: Option<SessionTimerState>,
    /// Per-call session timer override from Python script.
    pub session_timer_override: Option<crate::script::api::call::SessionTimerOverride>,
    /// Active transfer context (REFER handling).
    pub transfer: Option<super::transfer::TransferContext>,
    /// Set when this call's own INVITE carried a `Replaces` naming a dialog
    /// this node hosts. Acted on only once the script has admitted the INVITE
    /// (see [`PendingReplaces`]).
    pub pending_replaces: Option<PendingReplaces>,
    /// REFER subscriptions siphon owns for transfers in progress (RFC 3515).
    /// Present for the siphon-terminated inbound path (siphon is the notifier,
    /// sending `message/sipfrag` NOTIFYs to the referrer) and the
    /// siphon-originated path (`call.refer()`, siphon is the subscriber,
    /// receiving them from the referee). The transparent-forward path owns none
    /// — it bridges the peers' own NOTIFYs. A `Vec` so concurrent transfers on
    /// one dialog are disambiguated by the `Event: refer;id` token.
    pub refer_subscriptions: Vec<ReferSubscription>,
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
    /// Script-pinned B-leg Contact userpart (`call.set_contact_user()`). When
    /// set, the B-leg Contact becomes `<sip:user@advertised-host:port;transport>`
    /// instead of the default userless anchor. siphon still receives in-dialog
    /// requests (host:port unchanged) — the userpart just rides along.
    pub contact_user_override: Option<String>,
    /// Script-pinned B-leg Contact URI (`call.set_contact_uri()`). Full override
    /// of siphon's advertised Contact — the power tool for edge deployments that
    /// front siphon (GRUU, edge SBC). Overriding the host/port here moves the
    /// in-dialog anchor off siphon, so the deployment must route it back or the
    /// dialog breaks. Takes precedence over `contact_user_override`.
    pub contact_override: Option<String>,
    /// Pre-built ACK for the winning B-leg, deferred until A-leg ACKs (late ACK pattern).
    /// Contains (ACK message, transport, destination address).
    pub pending_b_leg_ack: Option<(
        SipMessage,
        crate::transport::Transport,
        std::net::SocketAddr,
    )>,
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
    /// When true (`call.dial(auth_passthrough=True)`), a B-leg 401/407 with no
    /// siphon-side credentials is relayed to the caller as a non-terminal
    /// challenge: the dispatcher forwards it and keeps the call alive instead of
    /// firing `@b2bua.on_failure`, deleting media, and removing the call — so the
    /// caller can authenticate end-to-end and re-INVITE (RFC 3261 §22.3).
    pub auth_passthrough: bool,
    /// Sequential-failover (LCR / `fork(strategy="sequential")`) state. `None`
    /// for a plain single dial or a parallel fork. See [`RouteSequenceState`].
    pub route_sequence: Option<RouteSequenceState>,
    /// The external control app this call was handed over to
    /// (`call.handover("app")`), if any. When `Some`, the call is *parked under
    /// control*: siphon holds the INVITE transaction un-dialed while the
    /// out-of-process app decides, and the answer-deadline sweep applies the
    /// handoff default action (not the 408 path) if the app never acts.
    pub control_app: Option<String>,
    /// Control-loss policy for a handed-over call ("hangup"/"continue"/
    /// "fallback"). Owned by the control plane on owner disconnect; stored here
    /// for observability.
    pub on_control_loss: Option<String>,
    /// True while a handed-over call is still awaiting the controller's first
    /// action. The answer-deadline sweep reads this to apply the handoff default
    /// instead of the 408 timeout teardown. Cleared once the controller acts
    /// (answer/progress transitions the state) or the call is torn down.
    pub handoff_pending: bool,
    /// True when siphon *placed* this call (`originate`) rather than receiving
    /// an INVITE for it. The A-leg is then a UAC dialog siphon owns, so every
    /// path that would answer the A-leg with a SIP *response* is wrong for it:
    /// an un-answered originate is abandoned with a CANCEL (RFC 3261 §9.1), not
    /// a 408/503 sent to the peer we are calling.
    pub originated: bool,
    /// The media anchor an originated call asked for, when it went out with no
    /// offer. Read on the callee's 2xx to answer its offer locally and carry the
    /// answer on the ACK (RFC 3261 §13.2.2.4). `None` for a call originated with
    /// a controller-supplied offer, and for every inbound call.
    pub originate_anchor: Option<OriginateAnchor>,
    /// This call's half of a bridge with another call this process owns, set
    /// while a `bridge` is forming and for as long as it holds. Mirrored on the
    /// peer's actor, so either side's teardown finds the other
    /// ([`super::bridge`]).
    pub bridge: Option<super::bridge::BridgeContext>,
}

/// The media plan of an offerless originate, resolved when the callee's 2xx
/// arrives. Names a profile in the media registry rather than carrying resolved
/// engine flags, so the actor layer stays free of media types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginateAnchor {
    /// Media profile whose `answer` flags the local anchor uses.
    pub profile: String,
    /// Per-call WebSocket bridge URI (templated), overriding the profile's.
    pub ws_uri: Option<String>,
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
            a_leg_local_addr: None,
            session_timer: None,
            session_timer_override: None,
            transfer: None,
            pending_replaces: None,
            refer_subscriptions: Vec::new(),
            outbound_credentials: None,
            digest_nc: crate::auth::NonceCounter::new(),
            li_record: false,
            preserve_call_id: false,
            from_host_override: None,
            to_host_override: None,
            contact_user_override: None,
            contact_override: None,
            pending_b_leg_ack: None,
            resolved_header_policy: None,
            a_leg_supports_100rel: false,
            auth_retry_count: 0,
            answer_deadline: None,
            auth_passthrough: false,
            route_sequence: None,
            control_app: None,
            on_control_loss: None,
            handoff_pending: false,
            originated: false,
            originate_anchor: None,
            bridge: None,
        }
    }

    /// Whether this call is parked under external control awaiting the
    /// controller's first action (the answer-deadline sweep uses this to apply
    /// the handoff default rather than the 408 teardown).
    pub fn is_handoff_pending(&self) -> bool {
        self.control_app.is_some() && self.handoff_pending
    }

    /// Pop the next carrier from the failover queue, mark it active, and return
    /// a clone. `None` when this is not a sequential call or the queue is empty
    /// (all carriers exhausted).
    pub fn take_next_route(&mut self) -> Option<crate::lcr::Route> {
        let sequence = self.route_sequence.as_mut()?;
        let route = sequence.pending.pop_front()?;
        sequence.active = Some(route.clone());
        sequence.active_since = Some(std::time::Instant::now());
        Some(route)
    }

    /// Record a failed attempt against the carrier that was in flight. No-op for
    /// a non-sequential call.
    ///
    /// Returns the attempt, so the caller can log it and hand it to
    /// `@b2bua.on_route_failure` without re-reading the actor.
    pub fn record_route_failure(&mut self, status_code: u16) -> Option<RouteAttempt> {
        let sequence = self.route_sequence.as_mut()?;
        let attempt = RouteAttempt {
            carrier_id: sequence
                .active
                .as_ref()
                .map(|route| route.carrier_id.clone())
                .unwrap_or_default(),
            status: status_code,
            elapsed_ms: sequence
                .active_since
                .map(|since| since.elapsed().as_millis() as u64)
                .unwrap_or_default(),
        };
        sequence.attempts.push(attempt.clone());
        Some(attempt)
    }

    /// Every failed attempt so far, in the order they were tried.
    pub fn route_attempts(&self) -> &[RouteAttempt] {
        self.route_sequence
            .as_ref()
            .map(|sequence| sequence.attempts.as_slice())
            .unwrap_or_default()
    }

    /// Whether more carriers remain to try in the failover queue.
    pub fn has_pending_routes(&self) -> bool {
        self.route_sequence
            .as_ref()
            .is_some_and(|sequence| !sequence.pending.is_empty())
    }

    /// Whether this call is running a sequential route/failover sequence.
    pub fn is_route_sequence(&self) -> bool {
        self.route_sequence.is_some()
    }

    /// The best (highest-priority) error seen across exhausted attempts
    /// (6xx > 5xx > 4xx), which is the code a fully-exhausted sequence surfaces
    /// to the A-leg. Derived from [`RouteSequenceState::attempts`] rather than
    /// accumulated, so the per-attempt record and the code the caller gets can
    /// never disagree.
    pub fn best_route_error(&self) -> Option<u16> {
        self.route_attempts()
            .iter()
            .map(|attempt| attempt.status)
            .reduce(|best, status| {
                if error_priority(best) >= error_priority(status) {
                    best
                } else {
                    status
                }
            })
    }

    /// The carrier currently in flight / that won (for `call.active_route`).
    pub fn active_route(&self) -> Option<&crate::lcr::Route> {
        self.route_sequence.as_ref().and_then(|s| s.active.as_ref())
    }

    /// Call-level send-socket pin applied to every sequential attempt.
    pub fn route_send_socket(&self) -> Option<&str> {
        self.route_sequence
            .as_ref()
            .and_then(|s| s.send_socket.as_deref())
    }

    /// Ring timeout for a route: its own `timeout_secs`, else the sequence
    /// default, else 30s.
    pub fn route_timeout(&self, route: &crate::lcr::Route) -> u32 {
        route.timeout_secs.unwrap_or_else(|| {
            self.route_sequence
                .as_ref()
                .map(|s| s.default_timeout)
                .unwrap_or(30)
        })
    }

    /// Number of not-yet-tried carriers (leak-test accessor).
    #[cfg(test)]
    pub fn pending_route_len(&self) -> usize {
        self.route_sequence
            .as_ref()
            .map(|s| s.pending.len())
            .unwrap_or(0)
    }

    /// Which leg an in-dialog request (re-INVITE / UPDATE / BYE) arrived on,
    /// determined by SIP dialog identity (RFC 3261 §12 — Call-ID, with the
    /// From-tag only as a tie-breaker), never by source socket.
    ///
    /// A peer that reconnects per transaction (TLS) or rebinds its NAT port
    /// sends the in-dialog request from a *different* source address than its
    /// original INVITE, so comparing sockets misroutes the request (it gets
    /// reflected back at the leg it came from). The Call-ID is stable across
    /// the dialog, so it is the correct discriminator.
    ///
    /// Returns `None` when the Call-ID matches no live dialog on this call —
    /// the caller answers 481 Call/Transaction Does Not Exist.
    pub fn request_direction(&self, sip_call_id: &str, from_tag: Option<&str>) -> Option<LegSide> {
        let a_match = self.a_leg.dialog.call_id == sip_call_id;
        let winner_b = self.winner.and_then(|index| self.b_legs.get(index));
        let b_match = winner_b.is_some_and(|leg| leg.dialog.call_id == sip_call_id);

        match (a_match, b_match) {
            (true, false) => Some(LegSide::A),
            (false, true) => Some(LegSide::B),
            (true, true) => {
                // Both legs carry the same Call-ID — `preserve_call_id` copies
                // the A-leg Call-ID onto the B-leg. Disambiguate by From-tag:
                // an in-dialog request's From-tag is the *peer's* own tag,
                // which is what we stored as each leg's `remote_tag`.
                let from_tag = from_tag?;
                if self.a_leg.dialog.remote_tag.as_deref() == Some(from_tag) {
                    Some(LegSide::A)
                } else if winner_b.and_then(|leg| leg.dialog.remote_tag.as_deref())
                    == Some(from_tag)
                {
                    Some(LegSide::B)
                } else {
                    None
                }
            }
            (false, false) => {
                // No winner yet (early dialog): an UPDATE (RFC 3311 §5.2) may
                // arrive on a not-yet-won fork leg. Match any real
                // (non-tracking) B-leg's Call-ID.
                if self.winner.is_none()
                    && self
                        .b_legs
                        .iter()
                        .any(|leg| !leg.is_tracking_leg() && leg.dialog.call_id == sip_call_id)
                {
                    Some(LegSide::B)
                } else {
                    None
                }
            }
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
        self.b_legs
            .iter()
            .enumerate()
            .find(|(_, leg)| leg.branch == branch)
    }

    /// Find a B-leg mutably by its Via branch.
    pub fn find_b_leg_by_branch_mut(&mut self, branch: &str) -> Option<(usize, &mut Leg)> {
        self.b_legs
            .iter_mut()
            .enumerate()
            .find(|(_, leg)| leg.branch == branch)
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
        self.b_leg_status
            .iter()
            .any(|s| matches!(s, BLegStatus::Ringing | BLegStatus::Answered))
    }

    /// Check if all B-legs have reached a terminal state.
    pub fn all_b_legs_settled(&self) -> bool {
        self.b_leg_status.iter().all(|s| {
            matches!(
                s,
                BLegStatus::Answered | BLegStatus::Failed(_) | BLegStatus::Cancelled
            )
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
    /// Local listener the ACK must leave from (the anchored leg's socket), when
    /// known. Preserves multi-homed source-port parity for the post-teardown
    /// re-ACK; `None` falls back to the default egress (single-listener hosts).
    pub local_addr: Option<SocketAddr>,
}

/// Post-teardown state for a leg whose INVITE was CANCELled but is still owed a
/// final response.
///
/// Two outcomes reach this entry, and both would otherwise be dropped as
/// "unknown branch" — the CANCEL paths remove the call, unregistering the leg's
/// branch, at the moment they put the CANCEL on the wire:
///
///  * the **ordinary** one, a `487 Request Terminated` (RFC 3261 §9.1): every
///    CANCELled INVITE draws a final non-2xx, and §17.1.1.3 makes ACKing it the
///    client transaction's job. Unacknowledged, the peer's INVITE server
///    transaction retransmits on Timer G until Timer H (64*T1 = 32 s, §17.2.1),
///    holding transaction state on both sides for the whole window.
///  * the **glare** one, a 2xx the callee put on the wire before our CANCEL
///    arrived (§9.1). That 2xx still establishes a dialog, which the B2BUA MUST
///    ACK (§13.2.2.4) and then BYE (§15) to release.
///
/// Keyed by the leg's SIP Call-ID. Auto-expires after 32 seconds (Timer H).
#[derive(Debug, Clone)]
pub struct ZombieCancelledLeg {
    /// The cancelled leg's dialog + transport, used to build the ACK and BYE.
    /// `remote_tag` / `remote_contact` are filled from the racing 2xx at
    /// handling time (they were unknown when the INVITE was CANCELled).
    pub leg: Leg,
    /// Request-URI of the INVITE that was CANCELled, captured at teardown.
    ///
    /// RFC 3261 §17.1.1.3 requires the ACK for a final non-2xx to carry the
    /// same Request-URI as the INVITE it acknowledges, and by the time the
    /// `487` lands the call — and with it the stashed INVITE — is gone. `None`
    /// only when the INVITE could not be read back (poisoned mutex); no ACK is
    /// built in that case, because a `sip:invalid` R-URI on the wire is worse
    /// than none.
    pub invite_ruri: Option<String>,
    /// Whether the BYE has already been sent. The first racing 2xx triggers
    /// ACK + BYE; later 200 OK retransmits re-ACK only (so a lost ACK still
    /// gets retried) without emitting a second BYE.
    pub byed: bool,
}

/// Outcome of an atomic answer claim ([`CallActorStore::try_win`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WinOutcome {
    /// This 2xx is the first to answer the call: the winner and `Answered`
    /// state were set under the per-call lock.
    FirstWin,
    /// The call was already answered — this 2xx is a retransmit of the winning
    /// B-leg's answer (or a losing fork branch). `b_leg_acked` reports whether
    /// the winning B-leg's ACK has already gone out, so the caller can re-ACK
    /// to stop the retransmit vs. absorb silently while awaiting the A-leg ACK.
    AlreadyAnswered { b_leg_acked: bool },
}

/// How long a torn-down call's SIP Call-IDs stay answerable with 481.
///
/// 32 s = Timer H / 64·T1 (RFC 3261 §17), the same expiry the zombie re-INVITE
/// and post-CANCEL absorbers use: once the peer's own client transaction has
/// timed out it stops retransmitting, so remembering the dialog past that point
/// buys nothing.
const TERMINATED_CALL_TTL: Duration = Duration::from_secs(32);

/// Hard ceiling on remembered torn-down Call-IDs.
///
/// Unlike the zombie absorbers — which only gain entries on rare paths — this
/// set gains an entry per leg on *every* teardown, so the TTL alone is not a
/// bound: at 40k cps it would hold 32 s × 40k ≈ 1.3M Call-IDs. The cap keeps the
/// footprint flat while still covering ~1.6 s of teardowns at that rate, far
/// wider than the sub-second glare window this exists for. At realistic per-NF
/// call rates the TTL evicts long before the cap is in play.
const TERMINATED_CALL_CAPACITY: usize = 65_536;

#[cfg(test)]
mod call_actor_footprint {
    use super::*;

    /// The call store holds a *pointer* to the actor, not the actor.
    ///
    /// `CallActor` is ~2.2 KB — an inline `a_leg: Leg`, the `b_legs` vectors,
    /// session-timer and transfer state — and `hashbrown` sizes its bucket
    /// array for the peak number of live calls and never shrinks it. Stored
    /// inline that was the largest retained bucket in siphon, held at the
    /// busiest moment the process ever saw for the rest of its life, with
    /// `call_count()` reading 0 the whole time.
    #[test]
    fn the_call_store_holds_a_pointer_not_the_actor() {
        let bucket = std::mem::size_of::<(String, Box<CallActor>)>();
        let key_only = std::mem::size_of::<String>();
        assert!(
            bucket <= key_only + 16,
            "call bucket is {bucket} B against a {key_only} B key — the actor is \
             being stored inline again, and the table will retain it at peak \
             concurrency forever"
        );
        // Guard the premise: boxing only pays while the payload is big.
        let payload = std::mem::size_of::<CallActor>();
        assert!(
            payload >= 512,
            "CallActor is down to {payload} B — re-check whether boxing still earns \
             its indirection"
        );
    }
}

/// Manages all active B2BUA calls.
///
/// Stores `CallActor` instances in a concurrent map, indexed by internal
/// call ID. Uses `LegRegistry` for SIP-level routing.
#[derive(Debug)]
pub struct CallActorStore {
    /// Internal call ID → CallActor.
    /// Boxed: `CallActor` is ~2.2 KB (an inline `a_leg: Leg`, the `b_legs`
    /// vectors, session-timer and transfer state), and `hashbrown` sizes its
    /// bucket array for the peak number of live calls and never shrinks it.
    /// Stored inline that is a ~2.3 KB bucket retained at the busiest moment
    /// the process ever saw, for the rest of its life, with `calls.len()`
    /// reading 0 — the same shape fixed for the transaction map and the timer
    /// wheel. Boxed the bucket is 32 bytes.
    calls: DashMap<String, Box<CallActor>>,
    /// SIP identifier routing table.
    pub registry: LegRegistry,
    /// Post-teardown re-INVITE ACK absorber, keyed by B-leg SIP Call-ID.
    pub zombie_reinvites: DashMap<String, ZombieReInviteEntry>,
    /// Post-CANCEL glare absorber (RFC 3261 §9.1): a 2xx that raced our CANCEL
    /// is ACKed + BYEd here, keyed by B-leg SIP Call-ID.
    pub zombie_cancelled: DashMap<String, ZombieCancelledLeg>,
    /// SIP Call-IDs of calls this node has torn down → when they were torn down,
    /// so a late in-dialog request naming one can be answered 481 instead of
    /// dropped ([`Self::is_recently_terminated`]). Read on the request path, so
    /// it is the lock-free half of the pair.
    terminated: DashMap<String, Instant>,
    /// Teardown order backing [`Self::terminated`], for eviction by age and by
    /// capacity. Only touched on teardown, never on the read path.
    ///
    /// A Call-ID can appear more than once — a peer may reuse one for its next
    /// call, and both B2BUA legs may share one. The timestamp doubles as a
    /// generation stamp so evicting a stale entry can't drop a Call-ID that has
    /// since been remembered again; see [`Self::evict_terminated`].
    terminated_order: Mutex<VecDeque<(String, Instant)>>,
}

impl CallActorStore {
    pub fn new() -> Self {
        Self {
            calls: DashMap::new(),
            registry: LegRegistry::new(),
            zombie_reinvites: DashMap::new(),
            zombie_cancelled: DashMap::new(),
            terminated: DashMap::new(),
            terminated_order: Mutex::new(VecDeque::new()),
        }
    }

    /// Remember `sip_call_id` as a dialog this node has torn down.
    ///
    /// Evicts from the front on the way in (amortised O(1), no timer task):
    /// entries older than [`TERMINATED_CALL_TTL`] first, then any overflow past
    /// [`TERMINATED_CALL_CAPACITY`].
    fn remember_terminated(&self, sip_call_id: &str) {
        if sip_call_id.is_empty() {
            return;
        }
        let mut order = match self.terminated_order.lock() {
            Ok(guard) => guard,
            Err(error) => {
                // Never remember without the order half — nothing would ever
                // evict it. A late in-dialog request for this call falls through
                // to the script instead of drawing a 481; that is the lesser
                // failure next to an unbounded map.
                warn!(
                    "terminated-call order mutex poisoned, not remembering {sip_call_id}: {error}"
                );
                return;
            }
        };
        // Always stamp and enqueue, even for a Call-ID already present: the
        // stamp is the generation, and the newest one is what must survive.
        let now = Instant::now();
        self.terminated.insert(sip_call_id.to_string(), now);
        order.push_back((sip_call_id.to_string(), now));
        Self::evict_terminated(
            &self.terminated,
            &mut order,
            now,
            TERMINATED_CALL_TTL,
            TERMINATED_CALL_CAPACITY,
        );
    }

    /// Drop remembered Call-IDs from the front of `order`: everything older than
    /// `ttl` as of `now`, then whatever still overflows `capacity`.
    ///
    /// An expiring entry only removes the Call-ID if its stamp is still the
    /// current generation. Without that check, re-terminating a Call-ID seen
    /// before would un-remember it: the stale entry ages out and takes the
    /// freshly-remembered Call-ID with it, which is how a peer that reuses
    /// Call-IDs across calls lost its 481.
    ///
    /// Split out (and given `now` / `ttl` / `capacity` explicitly) so both
    /// eviction rules are testable without a 32-second sleep.
    fn evict_terminated(
        terminated: &DashMap<String, Instant>,
        order: &mut VecDeque<(String, Instant)>,
        now: Instant,
        ttl: Duration,
        capacity: usize,
    ) {
        loop {
            let evict = match order.front() {
                Some((_, stamped)) => {
                    now.saturating_duration_since(*stamped) >= ttl || order.len() > capacity
                }
                None => false,
            };
            if !evict {
                break;
            }
            if let Some((call_id, stamped)) = order.pop_front() {
                terminated.remove_if(&call_id, |_, current| *current == stamped);
            }
        }
    }

    /// Did this node recently tear down a call carrying `sip_call_id`?
    ///
    /// An in-dialog request naming it can no longer be bridged or routed — both
    /// dialogs are gone here — so it MUST be answered 481 Call/Transaction Does
    /// Not Exist (RFC 3261 §12.2.2, §15.1.2 for BYE) rather than dropped.
    /// Dropping it leaves the peer retransmitting to its own timer F; a VoNR UE
    /// reads that 32 s silence as a dead IMS and recovers by releasing its IMS
    /// PDU session and re-registering, which costs ~40 s of terminating service.
    ///
    /// Eviction is lazy (it happens on insert), so an entry can outlive the TTL
    /// by a while. That is harmless — the answer is still correct — and it keeps
    /// this to a single hash on the request path.
    pub fn is_recently_terminated(&self, sip_call_id: &str) -> bool {
        !sip_call_id.is_empty() && self.terminated.contains_key(sip_call_id)
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
        self.calls.insert(id.clone(), Box::new(call));
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
    /// Reports which leg matched as well as which call, because the party that
    /// survives a takeover is the *peer* of the named dialog and the caller
    /// cannot work that out from the call id alone.
    pub fn find_call_by_replaces_dialog(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<ReplacesMatch> {
        for entry in self.calls.iter() {
            let call = entry.value();
            let leg_matches = |leg: &Leg| {
                leg.dialog.call_id == call_id
                    && leg.dialog.local_tag == to_tag
                    && (leg.dialog.remote_tag.as_deref() == Some(from_tag))
            };
            if leg_matches(&call.a_leg) {
                return Some(ReplacesMatch {
                    call_id: entry.key().clone(),
                    on_a_leg: true,
                });
            }
            if call.b_legs.iter().any(leg_matches) {
                return Some(ReplacesMatch {
                    call_id: entry.key().clone(),
                    on_a_leg: false,
                });
            }
        }
        None
    }

    /// Record the `Replaces` match resolved for a call still being admitted.
    pub fn set_pending_replaces(&self, call_id: &str, pending: PendingReplaces) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.pending_replaces = Some(pending);
        }
    }

    /// Take the recorded `Replaces` match, if any, leaving none behind.
    pub fn take_pending_replaces(&self, call_id: &str) -> Option<PendingReplaces> {
        self.calls
            .get_mut(call_id)
            .and_then(|mut call| call.pending_replaces.take())
    }

    /// Lift a call's A-leg out and drop the (now empty) call, WITHOUT retiring
    /// the dialog.
    ///
    /// The leg is moving to another call, not ending, so this deliberately does
    /// none of what [`remove_call`](Self::remove_call) does: the Call-ID keeps
    /// its registry entry (re-pointed by [`adopt_replaced_dialog`]) and is never
    /// marked terminated, because doing either would make the ACK for the 200
    /// this leg is about to receive resolve to nothing and answer 481.
    ///
    /// [`adopt_replaced_dialog`]: Self::adopt_replaced_dialog
    pub fn detach_a_leg_for_adoption(&self, call_id: &str) -> Option<Leg> {
        let (_, call) = self.calls.remove(call_id)?;
        call.shutdown_actors();
        self.registry.remove_branch(&call.a_leg.branch);
        Some(call.a_leg)
    }

    /// Hand a call's dialog over to a new party (RFC 3891 `Replaces`).
    ///
    /// `new_leg` takes the place of the leg named by the `Replaces`, and the
    /// call is rebuilt around the pair that is left: the new leg in the A-leg
    /// slot and the surviving party as the sole B-leg. The A-leg slot is not
    /// negotiable — the inbound-ACK path resolves a call by Call-ID and then
    /// marks `a_leg` acked, so a UAS leg parked anywhere else would never have
    /// its ACK recorded and would retransmit its 200 to Timer B.
    ///
    /// Returns the replaced leg so the caller can BYE it (RFC 3891 §3 requires
    /// the replaced dialog to be terminated once the new INVITE is accepted),
    /// together with the survivor.
    ///
    /// The replaced dialog is retired here — registry entries dropped and the
    /// Call-ID remembered as terminated — so a late in-dialog request on it
    /// answers 481 rather than resolving to a call it is no longer part of.
    pub fn adopt_replaced_dialog(
        &self,
        replaced_call_id: &str,
        replaced_on_a_leg: bool,
        new_leg: Leg,
    ) -> Option<(Leg, Leg)> {
        let new_sip_call_id = new_leg.dialog.call_id.clone();
        let new_branch = new_leg.branch.clone();
        let (replaced, survivor) = {
            let mut call = self.calls.get_mut(replaced_call_id)?;
            let winner = call.winner?;
            if winner >= call.b_legs.len() {
                return None;
            }
            let (replaced, survivor) = if replaced_on_a_leg {
                let survivor = call.b_legs.swap_remove(winner);
                let replaced = std::mem::replace(&mut call.a_leg, new_leg);
                (replaced, survivor)
            } else {
                let replaced = call.b_legs.swap_remove(winner);
                // The old A-leg becomes the surviving B-leg; the new party takes
                // the A-leg slot it vacates.
                let survivor = std::mem::replace(&mut call.a_leg, new_leg);
                (replaced, survivor)
            };
            // Rebuild around the surviving pair. Any other B-leg on the call is
            // a settled fork loser and has no dialog left to carry over.
            call.b_legs.clear();
            call.b_leg_status.clear();
            call.b_leg_handles.clear();
            call.b_legs.push(survivor.clone());
            call.b_leg_status.push(BLegStatus::Answered);
            call.b_leg_handles.push(None);
            call.winner = Some(0);
            call.state = CallState::Answered;
            (replaced, survivor)
        };

        // The new party's dialog now belongs to this call, so its Call-ID has to
        // resolve here — its ACK, re-INVITEs and BYE all arrive on it.
        self.registry
            .register_call_id(&new_sip_call_id, replaced_call_id);
        self.registry.register_branch(&new_branch, replaced_call_id);

        self.registry.remove_call_id(&replaced.dialog.call_id);
        self.registry.remove_branch(&replaced.branch);
        self.remember_terminated(&replaced.dialog.call_id);

        Some((replaced, survivor))
    }

    /// Resolve the `Replaces` triple a referrer supplied (its own view of the
    /// dialog to be replaced) into the triple the *far* party of that dialog
    /// would recognise, together with the internal call id the dialog belongs to.
    ///
    /// On a B2BUA the two ends of a call never share dialog identifiers: the
    /// referrer names its held call by the Call-ID and tag pair of the leg
    /// facing *it*, while the transfer target only knows the leg facing itself.
    /// A `Replaces` forwarded verbatim therefore names a dialog the target has
    /// never seen, and RFC 3891 §3 requires it to answer `481`. This returns the
    /// far leg's identifiers *as the far party sees them* — its Call-ID,
    /// siphon's local tag as the `from-tag`, and the far party's own tag as the
    /// `to-tag` (RFC 3891 §3 matches those against the remote and local tag of
    /// the dialog at the receiving UAS, respectively).
    ///
    /// `None` when the dialog is not one this node hosts (a referrer
    /// transferring against a call that never traversed siphon), when the far
    /// leg has no tag yet (nothing to replace), or when the far leg has not been
    /// chosen — the caller passes the referrer's own triple through in that case.
    pub fn replaces_as_seen_by_peer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<(String, ReplacesDialog)> {
        for entry in self.calls.iter() {
            let call = entry.value();
            let matches = |leg: &Leg| {
                leg.dialog.call_id == call_id
                    && leg.dialog.local_tag == to_tag
                    && leg.dialog.remote_tag.as_deref() == Some(from_tag)
            };
            let peer = if matches(&call.a_leg) {
                call.winner.and_then(|index| call.b_legs.get(index))
            } else if call.b_legs.iter().any(matches) {
                Some(&call.a_leg)
            } else {
                continue;
            }?;
            return Some((
                entry.key().clone(),
                ReplacesDialog {
                    call_id: peer.dialog.call_id.clone(),
                    from_tag: peer.dialog.local_tag.clone(),
                    to_tag: peer.dialog.remote_tag.clone()?,
                },
            ));
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

    /// RFC 3262 auto-PRACK dedup: returns `true` exactly once for each new RSeq
    /// value seen on the given B-leg's early dialog (identified by its remote
    /// To-tag), and `false` for retransmits of an already-PRACKed reliable
    /// provisional. Used so the B2BUA emits a single PRACK per RSeq instead of
    /// one per 1xx retransmit. Keyed per To-tag so a forked pair of early
    /// dialogs — whose RSeq spaces are independent (RFC 3262 §3) and commonly
    /// both start at 1 — each get their own PRACK rather than the second being
    /// swallowed as a "retransmit" of the first.
    pub fn try_mark_prack_acked(
        &self,
        call_id: &str,
        b_leg_index: usize,
        to_tag: &str,
        rseq: u32,
    ) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let Some(leg) = call.b_legs.get_mut(b_leg_index) else {
            return false;
        };
        if leg.prack_acked_rseq.get(to_tag).is_some_and(|&v| v >= rseq) {
            return false;
        }
        leg.prack_acked_rseq.insert(to_tag.to_string(), rseq);
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
        self.calls
            .get(call_id)
            .map_or(0, |call| call.auth_retry_count)
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

    /// Record a siphon-originated REFER awaiting its response.
    pub fn register_originated_refer(&self, branch: &str, refer: OriginatedRefer) {
        self.registry.register_originated_refer(branch, refer);
    }

    /// Peek at the originated REFER a branch belongs to.
    pub fn lookup_originated_refer(&self, branch: &str) -> Option<OriginatedRefer> {
        self.registry.lookup_originated_refer(branch)
    }

    /// Take the originated REFER a branch belongs to, ending its transaction.
    pub fn take_originated_refer(&self, branch: &str) -> Option<OriginatedRefer> {
        self.registry.take_originated_refer(branch)
    }

    /// Drop any originated REFER still awaiting a response on this call.
    pub fn clear_originated_refers(&self, call_id: &str) {
        self.registry.clear_originated_refers(call_id);
    }

    /// Mark a call as one siphon *placed* (`originate`) and index its INVITE's
    /// Via branch so the response path routes to the UAC-side handler.
    pub fn mark_originated(&self, call_id: &str, branch: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.originated = true;
        }
        self.registry.register_originated_call(branch, call_id);
    }

    /// Whether this call was placed by siphon (`originate`).
    pub fn is_originated(&self, call_id: &str) -> bool {
        self.calls.get(call_id).is_some_and(|call| call.originated)
    }

    /// The internal call id of the originate whose INVITE carried `branch`.
    pub fn lookup_originated_call(&self, branch: &str) -> Option<String> {
        self.registry.lookup_originated_call(branch)
    }

    /// Record the media anchor an offerless originate must apply to the
    /// callee's 2xx offer.
    pub fn set_originate_anchor(&self, call_id: &str, anchor: OriginateAnchor) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.originate_anchor = Some(anchor);
        }
    }

    /// The media anchor plan of an originated call, if it went out offerless.
    pub fn originate_anchor(&self, call_id: &str) -> Option<OriginateAnchor> {
        self.calls
            .get(call_id)
            .and_then(|call| call.originate_anchor.clone())
    }

    /// Attach one half of a bridge to a call. Overwrites any previous half —
    /// the caller has already refused a leg that is `AlreadyBridged`.
    pub fn set_bridge(&self, call_id: &str, context: super::bridge::BridgeContext) -> bool {
        match self.calls.get_mut(call_id) {
            Some(mut call) => {
                call.bridge = Some(context);
                true
            }
            None => false,
        }
    }

    /// This call's half of a bridge, if it has one.
    pub fn bridge(&self, call_id: &str) -> Option<super::bridge::BridgeContext> {
        self.calls.get(call_id).and_then(|call| call.bridge.clone())
    }

    /// Advance this call's bridge to `stage`. Returns `false` when the call is
    /// gone or was never bridged, so a response arriving after teardown is a
    /// clean no-op rather than a resurrection.
    pub fn set_bridge_stage(&self, call_id: &str, stage: super::bridge::BridgeStage) -> bool {
        match self.calls.get_mut(call_id) {
            Some(mut call) => match call.bridge.as_mut() {
                Some(bridge) => {
                    bridge.stage = stage;
                    true
                }
                None => false,
            },
            None => false,
        }
    }

    /// Detach and return this call's half of a bridge. Idempotent: `None` when
    /// the call is gone or was not bridged.
    pub fn take_bridge(&self, call_id: &str) -> Option<super::bridge::BridgeContext> {
        self.calls
            .get_mut(call_id)
            .and_then(|mut call| call.bridge.take())
    }

    /// Get a call by internal ID.
    pub fn get_call(
        &self,
        call_id: &str,
    ) -> Option<dashmap::mapref::one::Ref<'_, String, Box<CallActor>>> {
        self.calls.get(call_id)
    }

    /// Get a mutable reference to a call.
    pub fn get_call_mut(
        &self,
        call_id: &str,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, Box<CallActor>>> {
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

    /// Atomically claim the answer for the B-leg at `index`.
    ///
    /// If the call is not yet `Answered`, sets the winner (which also flips the
    /// state to `Answered`) and returns [`WinOutcome::FirstWin`]. Otherwise the
    /// call was already answered — this 2xx is a retransmit of the winning
    /// B-leg's answer (or a losing fork branch) — and it returns
    /// [`WinOutcome::AlreadyAnswered`] with the winning B-leg's `initial_acked`.
    ///
    /// The check-and-set runs under the DashMap per-key lock, closing the race
    /// where two concurrent B-leg 200s both observe a stale "not answered"
    /// snapshot and both forward to the A-leg, delivering a duplicate 200 to a
    /// call the caller already ACKed.
    pub fn try_win(&self, call_id: &str, index: usize) -> WinOutcome {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return WinOutcome::AlreadyAnswered { b_leg_acked: false };
        };
        if call.state == CallState::Answered {
            let b_leg_acked = call
                .winner
                .and_then(|w| call.b_legs.get(w))
                .map(|leg| leg.initial_acked)
                .unwrap_or(false);
            WinOutcome::AlreadyAnswered { b_leg_acked }
        } else {
            call.set_winner(index);
            WinOutcome::FirstWin
        }
    }

    /// Atomically decide whether a 1xx provisional should be forwarded to the
    /// A-leg, moving the call `Calling -> Ringing` when it is.
    ///
    /// Returns `false` (drop the provisional) when the call is already
    /// `Answered`: a 1xx that arrives after the final response must not be
    /// forwarded, nor may it downgrade the confirmed dialog back to `Ringing`
    /// (RFC 3261 §12.1). Under multi-worker dispatch a B-leg's 180 and 200 —
    /// received in order but processed on different workers — can be handled
    /// concurrently; checking the call state under the per-call lock here (not
    /// a stale snapshot read ~1600 lines earlier) is what stops a late 180 from
    /// being forwarded behind its 200 and aborting the A-leg UAC.
    ///
    /// Returns `false` too when the call is gone (a provisional for a call that
    /// no longer exists is dropped).
    pub fn try_mark_ringing(&self, call_id: &str) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        if call.state == CallState::Answered {
            return false;
        }
        if call.state == CallState::Calling {
            call.state = CallState::Ringing;
        }
        true
    }

    /// Begin a sequential route/failover sequence for a call.
    pub fn start_route_sequence(&self, call_id: &str, sequence: RouteSequenceState) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.route_sequence = Some(sequence);
        }
    }

    /// Pop the next carrier for a call's failover queue (marks it active).
    pub fn take_next_route(&self, call_id: &str) -> Option<crate::lcr::Route> {
        self.calls.get_mut(call_id)?.take_next_route()
    }

    /// Record a failed attempt against a call's in-flight carrier, returning it
    /// so the caller can log it and dispatch `@b2bua.on_route_failure`.
    pub fn record_route_failure(&self, call_id: &str, status_code: u16) -> Option<RouteAttempt> {
        self.calls
            .get_mut(call_id)?
            .record_route_failure(status_code)
    }

    /// Every failed attempt of a call's failover sequence, in order tried.
    pub fn route_attempts(&self, call_id: &str) -> Vec<RouteAttempt> {
        self.calls
            .get(call_id)
            .map(|call| call.route_attempts().to_vec())
            .unwrap_or_default()
    }

    /// Whether a call has more carriers to try in its failover queue.
    pub fn has_pending_routes(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.has_pending_routes())
    }

    /// Mark every not-yet-settled B-leg (Trying/Ringing) as Cancelled — used
    /// when a failover-advance CANCELs the in-flight carrier, so that carrier's
    /// stray `487 Request Terminated` is absorbed rather than mistaken for a
    /// fresh carrier failure (which would trigger another advance).
    pub fn mark_active_b_legs_cancelled(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            for status in call.b_leg_status.iter_mut() {
                if matches!(status, BLegStatus::Trying | BLegStatus::Ringing) {
                    *status = BLegStatus::Cancelled;
                }
            }
        }
    }

    /// Whether a call is running a sequential route/failover sequence.
    pub fn is_route_sequence(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.is_route_sequence())
    }

    /// The best (highest-priority) error across a call's exhausted attempts.
    pub fn best_route_error(&self, call_id: &str) -> Option<u16> {
        self.calls
            .get(call_id)
            .and_then(|call| call.best_route_error())
    }

    /// When the call was created — i.e. when its A-leg INVITE arrived.  Rf
    /// charging needs it to stamp `SIP-Request-Timestamp` on a record built at
    /// answer time (TS 32.299 §7.2.183).
    pub fn created_at(&self, call_id: &str) -> Option<std::time::Instant> {
        self.calls.get(call_id).map(|call| call.created_at)
    }

    /// The carrier route currently in flight / that won, cloned.
    pub fn active_route(&self, call_id: &str) -> Option<crate::lcr::Route> {
        self.calls
            .get(call_id)
            .and_then(|call| call.active_route().cloned())
    }

    /// The call-level send-socket pin for a call's sequential attempts, cloned.
    pub fn route_send_socket(&self, call_id: &str) -> Option<String> {
        self.calls
            .get(call_id)
            .and_then(|call| call.route_send_socket().map(String::from))
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

    /// Record a siphon-owned REFER subscription for a transfer in progress.
    pub fn push_refer_subscription(&self, call_id: &str, subscription: ReferSubscription) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.refer_subscriptions.push(subscription);
        }
    }

    /// True if the call carries a siphon-owned *subscriber* REFER subscription
    /// on the given leg (siphon-originated transfer: siphon sent the REFER and
    /// receives the referee's sipfrag NOTIFYs, rather than sending them).
    pub fn has_subscriber_refer_subscription(&self, call_id: &str, on_a_leg: bool) -> bool {
        self.calls
            .get(call_id)
            .map(|call| {
                call.refer_subscriptions.iter().any(|subscription| {
                    !subscription.siphon_notifies && subscription.on_a_leg == on_a_leg
                })
            })
            .unwrap_or(false)
    }

    /// Record that the referrer of an in-flight siphon-terminated transfer has
    /// ended its dialog (sent BYE) before the dialed target resolved, and report
    /// whether that was the case.
    ///
    /// `true` means the BYE closed the *referrer's* leg of a transfer that is
    /// still running, so the call must NOT be torn down: the surviving party is
    /// waiting to be bridged to the transfer target (RFC 5589 §7 — the
    /// transferor is free to leave as soon as the REFER is accepted). Every
    /// matching notifier subscription is flagged so the completion path skips
    /// the terminating NOTIFY and the referrer BYE it can no longer deliver
    /// (RFC 3515 §2.4.4 — the implicit subscription died with the dialog).
    ///
    /// `false` for every other BYE — a plain hangup, the surviving party's own
    /// BYE, a transparent-mode transfer (siphon owns no subscription there), or
    /// a transfer whose target already resolved — and those take the normal
    /// teardown path unchanged.
    ///
    /// Idempotent: a retransmitted BYE re-flags an already-flagged subscription
    /// and still reports `true`, so the retransmission is answered the same way
    /// rather than falling through to a teardown.
    pub fn mark_transfer_referrer_gone(&self, call_id: &str, on_a_leg: bool) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        let mut matched = false;
        for subscription in call.refer_subscriptions.iter_mut() {
            if subscription.siphon_notifies
                && subscription.on_a_leg == on_a_leg
                && subscription.target_leg_call_id.is_some()
            {
                subscription.referrer_gone = true;
                matched = true;
            }
        }
        matched
    }

    /// True when the referrer of the in-flight siphon-terminated transfer on
    /// this leg has already left (see [`mark_transfer_referrer_gone`]).
    ///
    /// [`mark_transfer_referrer_gone`]: Self::mark_transfer_referrer_gone
    pub fn transfer_referrer_gone(&self, call_id: &str, on_a_leg: bool) -> bool {
        self.calls
            .get(call_id)
            .map(|call| {
                call.refer_subscriptions.iter().any(|subscription| {
                    subscription.siphon_notifies
                        && subscription.on_a_leg == on_a_leg
                        && subscription.referrer_gone
                })
            })
            .unwrap_or(false)
    }

    /// Drop any REFER subscriptions recorded on the given leg (e.g. on the
    /// terminating NOTIFY of a siphon-owned subscription).
    pub fn clear_refer_subscriptions_on_leg(&self, call_id: &str, on_a_leg: bool) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.refer_subscriptions
                .retain(|subscription| subscription.on_a_leg != on_a_leg);
        }
    }

    /// Reserve the next local CSeq for one leg of a call (increments the stored
    /// value and returns the number to use). Returns `None` if the call or the
    /// requested leg is not present. Used for siphon-originated in-dialog
    /// requests on a leg (REFER-subscription NOTIFYs, outbound REFER).
    pub fn reserve_leg_cseq(&self, call_id: &str, on_a_leg: bool) -> Option<u32> {
        let mut call = self.calls.get_mut(call_id)?;
        let winner = call.winner;
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            winner.and_then(|index| call.b_legs.get_mut(index))
        }?;
        let cseq = leg.dialog.local_cseq;
        leg.dialog.local_cseq += 1;
        Some(cseq)
    }

    /// Reserve siphon's owned SDP `o=` identity for the next SDP emitted toward
    /// one leg of a call: returns `(sdp_session_id, sdp_version)` and
    /// post-increments the stored version so the next emit is strictly greater
    /// (RFC 3264 §8). Returns `None` if the call or the requested leg is absent.
    /// The session-id is stable for the dialog's life; only the version advances.
    pub fn reserve_leg_sdp_version(&self, call_id: &str, on_a_leg: bool) -> Option<(u64, u64)> {
        let mut call = self.calls.get_mut(call_id)?;
        let winner = call.winner;
        let leg = if on_a_leg {
            Some(&mut call.a_leg)
        } else {
            winner.and_then(|index| call.b_legs.get_mut(index))
        }?;
        let identity = (leg.dialog.sdp_session_id, leg.dialog.sdp_version);
        leg.dialog.sdp_version += 1;
        Some(identity)
    }

    /// Reserve the SDP `o=` identity for a specific B-leg by index (used for a
    /// freshly-dialed leg — e.g. a transfer target — that is not the winner).
    pub fn reserve_b_leg_sdp_version_by_index(
        &self,
        call_id: &str,
        index: usize,
    ) -> Option<(u64, u64)> {
        let mut call = self.calls.get_mut(call_id)?;
        let leg = call.b_legs.get_mut(index)?;
        let identity = (leg.dialog.sdp_session_id, leg.dialog.sdp_version);
        leg.dialog.sdp_version += 1;
        Some(identity)
    }

    /// Record one leg's own most-recent endpoint SDP (raw). Stored so a
    /// siphon-terminated transfer can offer the surviving leg's real media to
    /// the transfer target. `on_a_leg` selects the A-leg or the winning B-leg;
    /// a no-op if the call or leg is absent, or if `sdp` is empty.
    pub fn set_leg_last_sdp(&self, call_id: &str, on_a_leg: bool, sdp: &[u8]) {
        if sdp.is_empty() {
            return;
        }
        if let Some(mut call) = self.calls.get_mut(call_id) {
            let winner = call.winner;
            let leg = if on_a_leg {
                Some(&mut call.a_leg)
            } else {
                winner.and_then(|index| call.b_legs.get_mut(index))
            };
            if let Some(leg) = leg {
                leg.last_sdp = Some(sdp.to_vec());
            }
        }
    }

    /// Clone one leg of a call (the A-leg, or the winning B-leg). Used to build
    /// siphon-originated in-dialog requests off a snapshot without holding the
    /// call lock across the send.
    pub fn clone_leg(&self, call_id: &str, on_a_leg: bool) -> Option<Leg> {
        let call = self.calls.get(call_id)?;
        if on_a_leg {
            Some(call.a_leg.clone())
        } else {
            call.winner
                .and_then(|index| call.b_legs.get(index).cloned())
        }
    }

    /// Complete a siphon-terminated transfer: promote the just-answered transfer
    /// target (`target_idx` in `b_legs`) to be the surviving party's new peer,
    /// and return the referrer leg (the party being transferred away) so the
    /// caller can BYE it.
    ///
    /// - `referrer_on_a_leg == true` — the referrer is the A-leg and the
    ///   surviving party is the winning B-leg: the target replaces the A-leg (it
    ///   becomes the new `a_leg`, the winner is preserved, the old A-leg is
    ///   returned). This is the Microsoft Teams blind-transfer shape.
    /// - `referrer_on_a_leg == false` — the referrer is the winning B-leg and the
    ///   surviving party is the A-leg: the target becomes the new winner and the
    ///   old winning B-leg is returned.
    ///
    /// The parallel per-B-leg vectors are kept aligned when a slot is removed.
    pub fn promote_transfer_target(
        &self,
        call_id: &str,
        target_idx: usize,
        referrer_on_a_leg: bool,
    ) -> Option<Leg> {
        let mut call = self.calls.get_mut(call_id)?;
        if target_idx >= call.b_legs.len() {
            return None;
        }
        if referrer_on_a_leg {
            let target = call.b_legs.remove(target_idx);
            if target_idx < call.b_leg_status.len() {
                call.b_leg_status.remove(target_idx);
            }
            if target_idx < call.b_leg_handles.len() {
                call.b_leg_handles.remove(target_idx);
            }
            // Removing the slot shifts higher indices down by one — fix the
            // winner pointer (the surviving B-leg) accordingly.
            match call.winner {
                Some(winner) if winner == target_idx => call.winner = None,
                Some(winner) if winner > target_idx => call.winner = Some(winner - 1),
                _ => {}
            }
            let old_referrer = std::mem::replace(&mut call.a_leg, target);
            drop(call);
            self.retire_promoted_referrer(&old_referrer);
            Some(old_referrer)
        } else {
            let old_winner_idx = call.winner?;
            let old_referrer = call.b_legs.get(old_winner_idx).cloned()?;
            call.winner = Some(target_idx);
            drop(call);
            self.retire_promoted_referrer(&old_referrer);
            Some(old_referrer)
        }
    }

    /// Retire the dialog the transfer promoted away from.
    ///
    /// The referrer's leg leaves the call at promotion, so `remove_call` will
    /// never see it at teardown — it only walks the legs still attached. Without
    /// this its `Call-ID → call` registry entry outlives the call forever, and
    /// the next INVITE that reuses that Call-ID matches the dispatcher's
    /// "call already exists" guard and is silently absorbed as a retransmission:
    /// the caller gets no response at all, not even a 100. Retiring it here also
    /// makes a late in-dialog request on the retired dialog answer 481 rather
    /// than resolving to a call that has moved on (RFC 3261 §12.2.2), which is
    /// the same treatment every other torn-down leg gets.
    fn retire_promoted_referrer(&self, referrer: &Leg) {
        self.registry.remove_call_id(&referrer.dialog.call_id);
        self.registry.remove_branch(&referrer.branch);
        self.remember_terminated(&referrer.dialog.call_id);
    }

    /// Remove a call and clean up all registry entries.
    ///
    /// Sends `Shutdown` to all active B-leg actor handles before removing.
    /// B-leg entries with `reinvite_done:` or `reinvite:` target_uri are moved
    /// to `zombie_reinvites` so retransmitted 200 OKs can still be ACKed.
    ///
    /// Every leg's SIP Call-ID is remembered as terminated on the way out, so an
    /// in-dialog request that arrives after the teardown — the BYE glare where
    /// both parties hang up at once — is answered 481 rather than dropped. Both
    /// sides need it: on a B2BUA the A-leg and B-leg Call-IDs differ, and either
    /// peer can be the one whose BYE loses the race.
    pub fn remove_call(&self, call_id: &str) {
        if let Some((_, call)) = self.calls.remove(call_id) {
            // Shutdown any active B-leg actors
            call.shutdown_actors();
            // Any REFER siphon originated on this call is now moot — the call it
            // would transfer is gone. Cleared here rather than left to age out,
            // so an abandoned transfer does not leak an entry per call.
            self.registry.clear_originated_refers(call_id);
            // Likewise the originate branch index: one entry per placed call,
            // dropped with the call so it can never outlive it.
            self.registry.clear_originated_calls(call_id);
            // Clean up A-leg registry entries
            self.registry.remove_call_id(&call.a_leg.dialog.call_id);
            self.registry.remove_branch(&call.a_leg.branch);
            self.remember_terminated(&call.a_leg.dialog.call_id);
            // Clean up B-leg registry entries, preserving re-INVITE state
            for b_leg in &call.b_legs {
                self.registry.remove_call_id(&b_leg.dialog.call_id);
                self.registry.remove_branch(&b_leg.branch);
                self.remember_terminated(&b_leg.dialog.call_id);
                // Move re-INVITE tracking entries to zombie map
                if let Some(ref target) = b_leg.dialog.target_uri {
                    if target.starts_with("reinvite_done:") || target.starts_with("reinvite:") {
                        self.zombie_reinvites.insert(
                            b_leg.dialog.call_id.clone(),
                            ZombieReInviteEntry {
                                destination: b_leg.transport.remote_addr,
                                transport: b_leg.transport.transport,
                                local_addr: b_leg.transport.local_addr,
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
    /// leg (INVITE sent, no final response yet — status `Trying`/`Ringing`) as
    /// a [`ZombieCancelledLeg`], so the final response the CANCEL provokes is
    /// still answerable after the call is gone: the ordinary `487` gets its ACK
    /// (RFC 3261 §17.1.1.3) and a 2xx that raced the CANCEL (§9.1) gets ACK
    /// (§13.2.2.4) + BYE (§15). Used by the CANCEL paths in place of
    /// `remove_call`.
    ///
    /// Returns true if any zombie-cancelled entries were captured (so the
    /// caller can schedule their expiry).
    pub fn remove_call_after_cancel(&self, call_id: &str) -> bool {
        let mut captured = false;
        if let Some(call) = self.calls.get(call_id) {
            // A call siphon placed (`originate`) carries its pending INVITE on
            // the A-leg, not a B-leg, so the loop below would capture nothing
            // and the final response to our CANCEL would be dropped — leaving
            // the callee retransmitting a 487 nobody ACKs (RFC 3261 §17.1.1.3),
            // or a 200 for a dialog nobody ACKs or BYEs (§9.1 glare, §13.2.2.4,
            // §15).
            if call.originated && matches!(call.state, CallState::Calling | CallState::Ringing) {
                if let Some(invite) = call.a_leg_invite.as_ref() {
                    self.zombie_cancelled.insert(
                        call.a_leg.dialog.call_id.clone(),
                        ZombieCancelledLeg {
                            leg: call.a_leg.clone(),
                            invite_ruri: request_uri_of(invite),
                            byed: false,
                        },
                    );
                    captured = true;
                }
            }
            for (index, b_leg) in call.b_legs.iter().enumerate() {
                let pending = matches!(
                    call.b_leg_status.get(index),
                    Some(BLegStatus::Trying) | Some(BLegStatus::Ringing)
                );
                // Only legs whose INVITE actually went on the wire can answer.
                if pending {
                    if let Some(invite) = b_leg.b_leg_invite.as_ref() {
                        self.zombie_cancelled.insert(
                            b_leg.dialog.call_id.clone(),
                            ZombieCancelledLeg {
                                leg: b_leg.clone(),
                                invite_ruri: request_uri_of(invite),
                                byed: false,
                            },
                        );
                        captured = true;
                    }
                }
            }
        }
        self.remove_call(call_id);
        captured
    }

    /// Resolve a racing 2xx to a CANCELled leg by SIP Call-ID.
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

    /// Resolve a final non-2xx — in practice the `487 Request Terminated` that
    /// RFC 3261 §9.1 makes the ordinary outcome of a CANCEL — to a CANCELled
    /// leg by SIP Call-ID.
    ///
    /// Returns the captured leg and the CANCELled INVITE's Request-URI, so the
    /// caller can build the ACK §17.1.1.3 requires on the INVITE's own branch.
    ///
    /// Unlike [`Self::zombie_cancelled_for_2xx`] there is no first-response
    /// flag: the ACK for a final non-2xx belongs to the INVITE's client
    /// transaction, which §17.1.1.3 has re-pass it to the transport on *every*
    /// retransmission of the response while it sits in `Completed`. Answering
    /// only the first would leave a peer whose ACK was lost retransmitting to
    /// Timer H regardless — the exact stall this entry exists to end.
    pub fn zombie_cancelled_for_non2xx(&self, sip_call_id: &str) -> Option<(Leg, Option<String>)> {
        self.zombie_cancelled
            .get(sip_call_id)
            .map(|entry| (entry.leg.clone(), entry.invite_ruri.clone()))
    }

    /// Iterate over all active calls (for session timer sweep).
    pub fn iter_calls(&self) -> dashmap::iter::Iter<'_, String, Box<CallActor>> {
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
        let stale_ids: Vec<String> = self
            .calls
            .iter()
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

    /// Mark a call parked under external control (`call.handover("app")`).
    /// Sets the control app + control-loss policy and flags the call as awaiting
    /// the controller's first action.
    pub fn set_control_owner(&self, call_id: &str, app: &str, on_control_loss: Option<&str>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.control_app = Some(app.to_string());
            call.on_control_loss = on_control_loss.map(String::from);
            call.handoff_pending = true;
        }
    }

    /// The control app owning a call, if any (cloned).
    pub fn control_app(&self, call_id: &str) -> Option<String> {
        self.calls
            .get(call_id)
            .and_then(|call| call.control_app.clone())
    }

    /// Record that the controlling app has acted on a parked call: clear the
    /// handoff deadline so the sweep no longer applies the default action, and
    /// clear the pending flag. Idempotent.
    pub fn mark_controller_acted(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if call.control_app.is_some() {
                call.handoff_pending = false;
                call.answer_deadline = None;
            }
        }
    }

    /// Release a parked call from external control: clear the control owner + the
    /// control-loss policy + the handoff-pending flag, so the call becomes an
    /// ordinary autonomous B2BUA call. Used when the controller hands control
    /// back to siphon with a routing decision (`route`): siphon dials the B-leg
    /// itself and owns the call thereafter. Clearing `control_app` is what
    /// disarms the handoff-timeout path in `fail_b2bua_call_on_timeout`
    /// (`is_handoff_pending` gates on `control_app.is_some()`), so a later B-leg
    /// ring-timeout takes the normal 408 path, not the parked-503 default.
    /// Idempotent.
    pub fn release_control_owner(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.control_app = None;
            call.on_control_loss = None;
            call.handoff_pending = false;
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
        self.calls
            .iter()
            .filter(|entry| {
                matches!(entry.state, CallState::Calling | CallState::Ringing)
                    && entry
                        .answer_deadline
                        .is_some_and(|deadline| now >= deadline)
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
// Process-wide call store handle (read-only observability)
// ---------------------------------------------------------------------------

/// The dispatcher-owned B2BUA call store, published for read-only consumers
/// (the admin API `/admin/calls`) that need to enumerate active calls without
/// owning the dispatcher.
static GLOBAL_CALL_STORE: std::sync::OnceLock<std::sync::Arc<CallActorStore>> =
    std::sync::OnceLock::new();

/// Register the process-wide B2BUA call store. Called once at dispatcher
/// construction; a no-op if a store was already registered.
pub fn set_global_call_store(store: std::sync::Arc<CallActorStore>) {
    let _ = GLOBAL_CALL_STORE.set(store);
}

/// The process-wide B2BUA call store, or `None` in headless / unit-test
/// contexts that never constructed a dispatcher.
pub fn global_call_store() -> Option<&'static std::sync::Arc<CallActorStore>> {
    GLOBAL_CALL_STORE.get()
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
    Provisional {
        leg_id: LegId,
        status_code: u16,
        message: SipMessage,
    },
    /// Success response (2xx).
    Answered { leg_id: LegId, message: SipMessage },
    /// Error response (3xx-6xx).
    Failed {
        leg_id: LegId,
        status_code: u16,
        message: SipMessage,
    },
    /// BYE received.
    Bye {
        leg_id: LegId,
        from_side: LegSide,
        message: SipMessage,
    },
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
    pub fn new(leg: Leg, call_tx: tokio::sync::mpsc::Sender<CallEvent>) -> (Self, LegHandle) {
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

        let _ = self
            .call_tx
            .send(CallEvent::Terminated {
                leg_id: self.leg.id.clone(),
            })
            .await;

        debug!(leg_id = %self.leg.id, "leg actor stopped");
    }

    async fn handle_sip_inbound(&mut self, message: SipMessage) {
        use crate::sip::message::Method;

        let method = message.method().cloned();
        let status = message.status_code();

        match (method, status) {
            (_, Some(code)) => {
                if (100..200).contains(&code) {
                    let _ = self
                        .call_tx
                        .send(CallEvent::Provisional {
                            leg_id: self.leg.id.clone(),
                            status_code: code,
                            message,
                        })
                        .await;
                } else if (200..300).contains(&code) {
                    if let Some(to_tag) = extract_to_tag(&message) {
                        self.leg.dialog.remote_tag = Some(to_tag);
                    }
                    let _ = self
                        .call_tx
                        .send(CallEvent::Answered {
                            leg_id: self.leg.id.clone(),
                            message,
                        })
                        .await;
                } else {
                    let _ = self
                        .call_tx
                        .send(CallEvent::Failed {
                            leg_id: self.leg.id.clone(),
                            status_code: code,
                            message,
                        })
                        .await;
                }
            }
            (Some(Method::Bye), _) => {
                let _ = self
                    .call_tx
                    .send(CallEvent::Bye {
                        leg_id: self.leg.id.clone(),
                        from_side: self.leg.side,
                        message,
                    })
                    .await;
            }
            (Some(Method::Invite), _) => {
                let _ = self
                    .call_tx
                    .send(CallEvent::ReInvite {
                        leg_id: self.leg.id.clone(),
                        message,
                    })
                    .await;
            }
            (Some(Method::Refer), _) => {
                let _ = self
                    .call_tx
                    .send(CallEvent::Refer {
                        leg_id: self.leg.id.clone(),
                        message,
                    })
                    .await;
            }
            _ => {}
        }
    }
}

/// Extract the To-tag from a SIP message.
pub fn extract_to_tag(message: &SipMessage) -> Option<String> {
    message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .and_then(|to| {
            to.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
}

/// The Request-URI of a stashed outbound request, as it went on the wire.
///
/// Read back for a leg being torn down, so an ACK built after the leg's INVITE
/// is gone still carries the Request-URI RFC 3261 §17.1.1.3 requires it to
/// share with the INVITE. Returns `None` on a poisoned mutex or a message that
/// is somehow not a request — the callers treat that as "cannot build an ACK",
/// which is the honest outcome; a placeholder R-URI on the wire is worse.
fn request_uri_of(stashed: &Arc<Mutex<SipMessage>>) -> Option<String> {
    let guard = match stashed.lock() {
        Ok(guard) => guard,
        Err(_) => {
            warn!("cancelled leg: stashed INVITE mutex poisoned, no Request-URI for its ACK");
            return None;
        }
    };
    match &guard.start_line {
        crate::sip::message::StartLine::Request(request_line) => {
            Some(request_line.request_uri.to_string())
        }
        _ => None,
    }
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
            local_addr: None,
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
                local_addr: None,
            },
        )
    }

    fn lcr_route(carrier: &str) -> crate::lcr::Route {
        crate::lcr::Route {
            carrier_id: carrier.to_string(),
            next_hop: Some(format!("sip:{carrier}.example:5060")),
            ..Default::default()
        }
    }

    // --- LCR sequential-failover state tests ---

    #[test]
    fn route_sequence_pops_in_order_and_drains() {
        let mut actor = CallActor::new(make_a_leg());
        actor.route_sequence = Some(RouteSequenceState {
            pending: [lcr_route("a"), lcr_route("b"), lcr_route("c")]
                .into_iter()
                .collect(),
            ..Default::default()
        });
        assert_eq!(actor.pending_route_len(), 3);
        assert!(actor.has_pending_routes());
        assert!(actor.is_route_sequence());

        let first = actor.take_next_route().expect("first carrier");
        assert_eq!(first.carrier_id, "a");
        // The popped carrier becomes the active (in-flight) route.
        assert_eq!(
            actor.active_route().map(|route| route.carrier_id.as_str()),
            Some("a")
        );
        assert_eq!(actor.pending_route_len(), 2);

        assert_eq!(actor.take_next_route().unwrap().carrier_id, "b");
        assert_eq!(actor.take_next_route().unwrap().carrier_id, "c");
        assert!(!actor.has_pending_routes());
        assert!(actor.take_next_route().is_none());
        // Active stays at the last carrier tried (the winner after a 2xx).
        assert_eq!(
            actor.active_route().map(|route| route.carrier_id.as_str()),
            Some("c")
        );
    }

    #[test]
    fn release_control_owner_clears_park_state() {
        // A call parked under external control (deferred handover) → the
        // controller hands control back with a routing decision. Releasing must
        // clear the owner + control-loss policy AND disarm the handoff-pending
        // path so a later B-leg ring-timeout takes the normal 408 route, not the
        // parked-503 default.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.set_control_owner(&call_id, "ivr-app", Some("hangup"));
        assert_eq!(store.control_app(&call_id).as_deref(), Some("ivr-app"));
        assert!(store
            .get_call(&call_id)
            .is_some_and(|call| call.is_handoff_pending()));

        store.release_control_owner(&call_id);

        assert!(store.control_app(&call_id).is_none());
        let call = store.get_call(&call_id).expect("call still present");
        assert!(
            !call.is_handoff_pending(),
            "handoff must be disarmed after release"
        );
        assert!(call.on_control_loss.is_none());
        // The call lives on — release does not remove it.
        assert!(matches!(call.state, CallState::Calling));
    }

    #[test]
    fn parked_call_unparks_into_route_sequence() {
        // Models the store-level transition b2bua_route_call performs: a parked
        // (deferred-handover) call, on a routing decision, is released from
        // control AND a sequential route sequence is started — so the shipped LCR
        // engine (b2bua_advance_route) then dials the B-leg. (The dispatcher
        // wiring around this is the same shipped rail the imperative fns use.)
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        // Park under control (deferred handover): Ringing + control owner.
        store.set_state(&call_id, CallState::Ringing);
        store.set_control_owner(&call_id, "ivr-app", Some("hangup"));
        assert!(!store.is_route_sequence(&call_id));

        // Route: release control, then start the sequential-failover queue.
        store.release_control_owner(&call_id);
        store.start_route_sequence(
            &call_id,
            RouteSequenceState {
                pending: [lcr_route("a"), lcr_route("b")].into_iter().collect(),
                ..Default::default()
            },
        );

        // The call is now an autonomous LCR sequence, no longer under control.
        assert!(store.is_route_sequence(&call_id));
        assert!(store.control_app(&call_id).is_none());
        assert!(store.has_pending_routes(&call_id));
        assert!(!store
            .get_call(&call_id)
            .is_some_and(|call| call.is_handoff_pending()));
        // The first carrier is dialable.
        assert_eq!(store.take_next_route(&call_id).unwrap().carrier_id, "a");
    }

    #[test]
    fn record_route_failure_keeps_highest_priority() {
        let mut actor = CallActor::new(make_a_leg());
        actor.route_sequence = Some(RouteSequenceState::default());
        actor.record_route_failure(486);
        assert_eq!(actor.best_route_error(), Some(486));
        // 5xx outranks 4xx.
        actor.record_route_failure(503);
        assert_eq!(actor.best_route_error(), Some(503));
        // A later lower-priority 404 does not displace the 503.
        actor.record_route_failure(404);
        assert_eq!(actor.best_route_error(), Some(503));
        // 6xx outranks everything.
        actor.record_route_failure(603);
        assert_eq!(actor.best_route_error(), Some(603));
    }

    /// Each failure is recorded against the carrier that was actually in
    /// flight, in the order tried — the record that used to be collapsed into a
    /// single best-error code, so a call that burned a carrier on its way to
    /// answering said nothing about which one.
    #[test]
    fn every_attempt_is_recorded_against_the_carrier_that_was_tried() {
        let mut actor = CallActor::new(make_a_leg());
        actor.route_sequence = Some(RouteSequenceState {
            pending: [lcr_route("a"), lcr_route("b"), lcr_route("c")]
                .into_iter()
                .collect(),
            ..Default::default()
        });

        actor.take_next_route().expect("carrier a");
        let first = actor.record_route_failure(503).expect("attempt recorded");
        assert_eq!(first.carrier_id, "a");
        assert_eq!(first.status, 503);

        actor.take_next_route().expect("carrier b");
        // A ring timeout is recorded like any other failure, as 408.
        let second = actor.record_route_failure(408).expect("attempt recorded");
        assert_eq!(second.carrier_id, "b");
        assert_eq!(second.status, 408);

        // Carrier c is dialled and answers, so it is never recorded as an
        // attempt — it is the winner, and reaches a script as `active_route`.
        actor.take_next_route().expect("carrier c");

        let carriers: Vec<&str> = actor
            .route_attempts()
            .iter()
            .map(|attempt| attempt.carrier_id.as_str())
            .collect();
        assert_eq!(carriers, ["a", "b"]);
        assert_eq!(
            actor.active_route().map(|route| route.carrier_id.as_str()),
            Some("c"),
            "the answering carrier is the winner, not an attempt"
        );
        // Derived from the attempts, so the code the A-leg would get and the
        // per-attempt record cannot disagree.
        assert_eq!(actor.best_route_error(), Some(503));
    }

    /// A call with no failover sequence has nothing to report, and asking must
    /// not be an error — every `Call` handed to a script reads this property,
    /// LCR or not.
    #[test]
    fn a_non_lcr_call_reports_no_attempts() {
        let mut actor = CallActor::new(make_a_leg());
        assert!(actor.route_attempts().is_empty());
        assert!(actor.record_route_failure(503).is_none());
    }

    #[test]
    fn non_sequential_call_has_no_route_state() {
        let mut actor = CallActor::new(make_a_leg());
        assert!(!actor.is_route_sequence());
        assert!(!actor.has_pending_routes());
        assert!(actor.take_next_route().is_none());
        assert_eq!(actor.best_route_error(), None);
        assert!(actor.active_route().is_none());
        assert_eq!(actor.pending_route_len(), 0);
    }

    // --- Leg tests ---

    #[test]
    fn leg_id_is_unique() {
        let id1 = LegId::new();
        let id2 = LegId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn dialog_has_stable_sdp_session_id_and_zero_version() {
        // Each dialog is born with a stable siphon-owned SDP session-id and a
        // version starting at 0 (RFC 4566 §5.2 / RFC 3264 §8).
        let a = Dialog::from_inbound("c@h".to_string(), "rt".to_string());
        assert_eq!(a.sdp_version, 0);
        let b = Dialog::new_outbound("c@h".to_string(), "lt".to_string(), "sip:x@h".to_string());
        assert_eq!(b.sdp_version, 0);
        // Distinct dialogs get distinct session-ids (overwhelmingly — u64 from a
        // v4 UUID).
        assert_ne!(a.sdp_session_id, b.sdp_session_id);
    }

    #[test]
    fn reserve_leg_sdp_version_is_monotonic_and_session_stable() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));
        store.set_winner(&call_id, 0);

        // A-leg: same session-id across reservations, version steps 0,1,2.
        let (a_sess0, v0) = store.reserve_leg_sdp_version(&call_id, true).unwrap();
        let (a_sess1, v1) = store.reserve_leg_sdp_version(&call_id, true).unwrap();
        let (a_sess2, v2) = store.reserve_leg_sdp_version(&call_id, true).unwrap();
        assert_eq!((v0, v1, v2), (0, 1, 2));
        assert_eq!(a_sess0, a_sess1);
        assert_eq!(a_sess1, a_sess2);

        // Winning B-leg counts independently under its own session-id.
        let (b_sess, bv0) = store.reserve_leg_sdp_version(&call_id, false).unwrap();
        let (_, bv1) = store.reserve_leg_sdp_version(&call_id, false).unwrap();
        assert_eq!((bv0, bv1), (0, 1));
        assert_ne!(a_sess0, b_sess, "each leg owns a distinct SDP session-id");

        // By-index variant advances the same B-leg counter.
        let (b_sess_idx, bv2) = store
            .reserve_b_leg_sdp_version_by_index(&call_id, 0)
            .unwrap();
        assert_eq!(bv2, 2);
        assert_eq!(b_sess_idx, b_sess);

        // Unknown call / index → None.
        assert!(store.reserve_leg_sdp_version("nope", true).is_none());
        assert!(store
            .reserve_b_leg_sdp_version_by_index(&call_id, 99)
            .is_none());
    }

    #[test]
    fn set_leg_last_sdp_records_per_leg_raw_body() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));
        store.set_winner(&call_id, 0);

        // Default: no SDP captured.
        assert!(store.get_call(&call_id).unwrap().a_leg.last_sdp.is_none());

        store.set_leg_last_sdp(&call_id, true, b"v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\n");
        store.set_leg_last_sdp(&call_id, false, b"v=0\r\no=bob 2 2 IN IP4 192.0.2.2\r\n");
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(
            call.a_leg.last_sdp.as_deref(),
            Some(&b"v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\n"[..])
        );
        assert_eq!(
            call.b_legs[0].last_sdp.as_deref(),
            Some(&b"v=0\r\no=bob 2 2 IN IP4 192.0.2.2\r\n"[..])
        );

        // Empty SDP is a no-op (does not clobber a stored body).
        store.set_leg_last_sdp(&call_id, true, b"");
        assert!(store.get_call(&call_id).unwrap().a_leg.last_sdp.is_some());
    }

    #[test]
    fn leg_stored_request_from_to_default_none_and_round_trip() {
        // Both constructors leave the verbatim request From/To capture empty —
        // only the transparent REFER/NOTIFY pseudo-legs populate it (RFC 3261
        // §8.2.6.2 verbatim echo). A leg that never captures them keeps the
        // dialog-reconstruction fallback.
        let mut a_leg = make_a_leg();
        assert_eq!(a_leg.stored_from, None);
        assert_eq!(a_leg.stored_to, None);
        let mut b_leg = make_b_leg(1);
        assert_eq!(b_leg.stored_from, None);
        assert_eq!(b_leg.stored_to, None);

        a_leg.stored_from = Some("<sip:bob@192.0.2.52>;tag=abc".to_string());
        a_leg.stored_to = Some("<sip:alice@192.0.2.50>;tag=xyz".to_string());
        assert_eq!(
            a_leg.stored_from.as_deref(),
            Some("<sip:bob@192.0.2.52>;tag=abc")
        );
        assert_eq!(
            a_leg.stored_to.as_deref(),
            Some("<sip:alice@192.0.2.50>;tag=xyz")
        );
        // A clone preserves the capture (the dispatcher clones legs when
        // snapshotting the call actor before relaying a response).
        b_leg.stored_from = a_leg.stored_from.clone();
        assert_eq!(b_leg.clone().stored_from, a_leg.stored_from);
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
        assert!(
            from.contains("tag=a-leg-remote-tag"),
            "From should have A-leg remote tag, got: {from}"
        );
        assert!(!from.contains("tag=b-leg-from-tag"));
        let to = msg.headers.get("To").unwrap();
        assert!(
            to.contains("tag=a-leg-local-tag"),
            "To should have A-leg local tag, got: {to}"
        );
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
        assert!(
            !to.contains(";tag="),
            "tagless To must remain tagless, got: {to}"
        );
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
        assert!(
            to.contains("tag=to-tag-original"),
            "To should be untouched, got: {to}"
        );
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
        assert_eq!(
            store.find_by_sip_call_id("call-1@10.0.0.1"),
            Some(call_id.clone())
        );
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

    /// The 2xx answer must be claimed atomically: the first `try_win` wins
    /// (sets the winner + `Answered`), and every subsequent 2xx (retransmit or
    /// losing fork branch) reports `AlreadyAnswered`. This is what stops two
    /// concurrent B-leg 200s from both forwarding to the A-leg and delivering a
    /// duplicate 200 to a caller that already ACKed.
    #[test]
    fn try_win_claims_the_answer_exactly_once() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));
        store.add_b_leg(&call_id, make_b_leg(1));

        // First 200 (B-leg 0) wins, setting winner + state atomically.
        assert_eq!(store.try_win(&call_id, 0), WinOutcome::FirstWin);
        {
            let call = store.get_call(&call_id).unwrap();
            assert_eq!(call.winner, Some(0));
            assert_eq!(call.state, CallState::Answered);
        }

        // A retransmit of the winner's 200 before the B-leg ACK went out:
        // already answered, absorb silently.
        assert_eq!(
            store.try_win(&call_id, 0),
            WinOutcome::AlreadyAnswered { b_leg_acked: false }
        );
        // A losing fork branch's 200 (B-leg 1): also already answered, not a win.
        assert_eq!(
            store.try_win(&call_id, 1),
            WinOutcome::AlreadyAnswered { b_leg_acked: false }
        );
        // The winner is unchanged (still B-leg 0).
        assert_eq!(store.get_call(&call_id).unwrap().winner, Some(0));

        // Once the winner's ACK has gone out, a further retransmit reports
        // acked=true so the caller re-ACKs to stop the UAS retransmitting.
        store.get_call_mut(&call_id).unwrap().b_legs[0].initial_acked = true;
        assert_eq!(
            store.try_win(&call_id, 0),
            WinOutcome::AlreadyAnswered { b_leg_acked: true }
        );
    }

    /// A 1xx provisional is forwarded (and moves Calling -> Ringing) until the
    /// call is answered; a late provisional reordered behind its 200 is then
    /// dropped and must NOT downgrade the confirmed dialog back to Ringing.
    /// This is the atomic guard that stops a late 180 processed on another
    /// worker from being forwarded to the A-leg after the final response.
    #[test]
    fn try_mark_ringing_drops_provisional_after_answer() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        // First 180: Calling -> Ringing, forward it.
        assert!(store.try_mark_ringing(&call_id));
        assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Ringing);
        // A second 180 while Ringing: still forwarded, stays Ringing.
        assert!(store.try_mark_ringing(&call_id));
        assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Ringing);

        // Answer the call.
        store.set_winner(&call_id, 0);
        assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Answered);

        // A late 180 reordered behind the 200: dropped, dialog NOT downgraded.
        assert!(!store.try_mark_ringing(&call_id));
        assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Answered);

        // A provisional for a call that no longer exists is dropped.
        assert!(!store.try_mark_ringing("nonexistent"));
    }

    /// The transferor may equally be the party siphon *called* — a callee
    /// transferring a call it answered is the everyday case. Then the named
    /// dialog is a B-leg, and the survivor is the A-leg.
    #[test]
    fn find_call_by_replaces_reports_a_b_leg_match() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let mut b_leg = make_b_leg(0);
        b_leg.dialog.remote_tag = Some("tag-callee".to_string());
        let b_call_id = b_leg.dialog.call_id.clone();
        let b_local_tag = b_leg.dialog.local_tag.clone();
        store.add_b_leg(&call_id, b_leg);
        store.set_winner(&call_id, 0);

        let matched = store.find_call_by_replaces_dialog(&b_call_id, "tag-callee", &b_local_tag);
        assert_eq!(
            matched,
            Some(ReplacesMatch {
                call_id,
                on_a_leg: false
            })
        );
    }

    #[test]
    fn pending_replaces_round_trips_and_is_taken_once() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let pending = PendingReplaces {
            replaced_call_id: "other-call".to_string(),
            replaced_on_a_leg: true,
            early_only: false,
        };
        store.set_pending_replaces(&call_id, pending.clone());
        assert_eq!(store.take_pending_replaces(&call_id), Some(pending));
        // Taken once — a second admission pass must not re-run the takeover.
        assert_eq!(store.take_pending_replaces(&call_id), None);
    }

    /// The leg is moving to another call, not ending. If the detach retired its
    /// Call-ID the ACK for the 200 it is about to receive would resolve to
    /// nothing and be answered 481, and the new party would retransmit its way
    /// to Timer B.
    #[test]
    fn detaching_a_leg_for_adoption_keeps_its_call_id_live() {
        let store = CallActorStore::new();
        let a_leg = make_a_leg();
        let sip_call_id = a_leg.dialog.call_id.clone();
        let call_id = store.create_call(a_leg);

        let detached = store.detach_a_leg_for_adoption(&call_id);
        assert!(detached.is_some());
        assert!(
            store.get_call(&call_id).is_none(),
            "the emptied call is dropped"
        );
        assert!(
            !store.is_recently_terminated(&sip_call_id),
            "the moving dialog must NOT be remembered as terminated"
        );
    }

    /// The transferor is the caller (its dialog is the A-leg): the new party
    /// takes the A-leg slot and the callee carries on as the sole B-leg.
    #[test]
    fn adopting_a_replaced_a_leg_rebuilds_the_call_around_the_new_party() {
        let store = CallActorStore::new();
        let a_leg = make_a_leg();
        let replaced_sip_call_id = a_leg.dialog.call_id.clone();
        let call_id = store.create_call(a_leg);
        let mut b_leg = make_b_leg(0);
        b_leg.dialog.remote_tag = Some("tag-callee".to_string());
        let survivor_sip_call_id = b_leg.dialog.call_id.clone();
        store.add_b_leg(&call_id, b_leg);
        store.set_winner(&call_id, 0);

        let mut new_leg = make_a_leg();
        new_leg.dialog.call_id = "takeover@10.0.0.9".to_string();
        new_leg.branch = "z9hG4bK-takeover".to_string();

        let (replaced, survivor) = store
            .adopt_replaced_dialog(&call_id, true, new_leg)
            .expect("the swap must succeed on an answered call");

        assert_eq!(replaced.dialog.call_id, replaced_sip_call_id);
        assert_eq!(survivor.dialog.call_id, survivor_sip_call_id);

        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.a_leg.dialog.call_id, "takeover@10.0.0.9");
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.b_legs[0].dialog.call_id, survivor_sip_call_id);
        assert_eq!(call.winner, Some(0));
        assert_eq!(call.state, CallState::Answered);
        drop(call);

        // The new party's dialog resolves here — its ACK/BYE arrive on it.
        assert_eq!(
            store.find_by_sip_call_id("takeover@10.0.0.9").as_deref(),
            Some(call_id.as_str())
        );
        // The replaced dialog is retired: gone from the registry and remembered
        // terminated, so a late in-dialog request on it answers 481.
        assert!(store.find_by_sip_call_id(&replaced_sip_call_id).is_none());
        assert!(store.is_recently_terminated(&replaced_sip_call_id));
    }

    /// The transferor is the callee (its dialog is the winning B-leg): the new
    /// party still lands in the A-leg slot — the inbound-ACK path only ever
    /// marks `a_leg` — and the original caller moves across to be the B-leg.
    #[test]
    fn adopting_a_replaced_b_leg_moves_the_caller_to_the_b_slot() {
        let store = CallActorStore::new();
        let a_leg = make_a_leg();
        let caller_sip_call_id = a_leg.dialog.call_id.clone();
        let call_id = store.create_call(a_leg);
        let mut b_leg = make_b_leg(0);
        b_leg.dialog.remote_tag = Some("tag-callee".to_string());
        let replaced_sip_call_id = b_leg.dialog.call_id.clone();
        store.add_b_leg(&call_id, b_leg);
        store.set_winner(&call_id, 0);

        let mut new_leg = make_a_leg();
        new_leg.dialog.call_id = "takeover-b@10.0.0.9".to_string();
        new_leg.branch = "z9hG4bK-takeover-b".to_string();

        let (replaced, survivor) = store
            .adopt_replaced_dialog(&call_id, false, new_leg)
            .expect("the swap must succeed on an answered call");

        assert_eq!(replaced.dialog.call_id, replaced_sip_call_id);
        assert_eq!(survivor.dialog.call_id, caller_sip_call_id);

        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.a_leg.dialog.call_id, "takeover-b@10.0.0.9");
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(
            call.b_legs[0].dialog.call_id, caller_sip_call_id,
            "the original caller survives as the B-leg"
        );
        assert_eq!(call.winner, Some(0));
        drop(call);

        assert!(store.is_recently_terminated(&replaced_sip_call_id));
        assert!(
            !store.is_recently_terminated(&caller_sip_call_id),
            "the survivor's dialog is untouched"
        );
    }

    /// A call that never answered has no negotiated media and no answered party
    /// to keep, so there is nothing to hand over.
    #[test]
    fn adopting_refuses_a_call_with_no_winner() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        let mut new_leg = make_a_leg();
        new_leg.dialog.call_id = "takeover-early@10.0.0.9".to_string();
        assert!(store
            .adopt_replaced_dialog(&call_id, true, new_leg)
            .is_none());
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
        assert_eq!(
            matched,
            Some(ReplacesMatch {
                call_id,
                on_a_leg: true
            })
        );
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

        let tag = "uas-early-tag";
        assert!(store.try_mark_prack_acked(&call_id, 0, tag, 42));
        // Same RSeq again — already PRACKed, returns false.
        assert!(!store.try_mark_prack_acked(&call_id, 0, tag, 42));
        // Earlier RSeq (out-of-order retransmit) — also no PRACK.
        assert!(!store.try_mark_prack_acked(&call_id, 0, tag, 1));
        // Higher RSeq (next reliable 1xx, e.g. 180 after 183) — PRACK it.
        assert!(store.try_mark_prack_acked(&call_id, 0, tag, 43));
    }

    /// Forked early dialogs on ONE INVITE branch have independent RSeq spaces
    /// (RFC 3262 §3) that commonly both start at 1. The dedup is keyed per
    /// remote To-tag, so each dialog's RSeq 1 gets its own PRACK — the second
    /// is NOT swallowed as a retransmit of the first.
    #[test]
    fn try_mark_prack_acked_per_early_dialog() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        // Two distinct early dialogs (two To-tags), each RSeq 1 → both PRACKed.
        assert!(store.try_mark_prack_acked(&call_id, 0, "tag-alpha", 1));
        assert!(store.try_mark_prack_acked(&call_id, 0, "tag-beta", 1));
        // Retransmit of each is still deduped independently.
        assert!(!store.try_mark_prack_acked(&call_id, 0, "tag-alpha", 1));
        assert!(!store.try_mark_prack_acked(&call_id, 0, "tag-beta", 1));
        // Each dialog advances its own RSeq independently.
        assert!(store.try_mark_prack_acked(&call_id, 0, "tag-alpha", 2));
        assert!(!store.try_mark_prack_acked(&call_id, 0, "tag-beta", 1));
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

    /// The ORDINARY outcome of a CANCEL, not the glare one: the peer answers
    /// the CANCELled INVITE `487 Request Terminated` (RFC 3261 §9.1), and
    /// §17.1.1.3 requires an ACK for it. The call is gone by then, so the ACK
    /// can only be built from the zombie entry — which therefore has to carry
    /// the CANCELled INVITE's Request-URI (§17.1.1.3: the ACK's Request-URI
    /// equals the INVITE's).
    #[test]
    fn store_zombie_captures_the_invite_ruri_so_the_487_can_be_acked() {
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());

        let mut sent_leg = make_b_leg(0);
        let sent_cid = sent_leg.dialog.call_id.clone();
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("198.51.100.20".to_string())
                    .with_user("bob".to_string())
                    .with_port(5060),
            )
            .via("SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-bleg0".to_string())
            .from("<sip:alice@198.51.100.10>;tag=a".to_string())
            .to("<sip:bob@198.51.100.20>".to_string())
            .call_id(sent_cid.clone())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        sent_leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
        store.add_b_leg(&call_id, sent_leg);

        // A leg whose INVITE never went on the wire draws no final response, so
        // it is not captured and nothing is owed an ACK.
        let unsent_leg = make_b_leg(1);
        let unsent_cid = unsent_leg.dialog.call_id.clone();
        store.add_b_leg(&call_id, unsent_leg);

        assert!(store.remove_call_after_cancel(&call_id));

        let (leg, ruri) = store
            .zombie_cancelled_for_non2xx(&sent_cid)
            .expect("the CANCELled leg must still resolve for its 487");
        assert_eq!(leg.dialog.call_id, sent_cid);
        // The ACK goes out on the INVITE's own branch (§17.1.1.3), which is the
        // leg's branch — not a fresh one.
        assert_eq!(leg.branch, "z9hG4bK-bleg0");
        assert_eq!(ruri.as_deref(), Some("sip:bob@198.51.100.20:5060"));
        assert!(store.zombie_cancelled_for_non2xx(&unsent_cid).is_none());

        // §17.1.1.3 has the client transaction re-pass the ACK to the transport
        // on EVERY retransmission of the final response while it sits in
        // Completed — so the lookup must keep resolving, not consume the entry.
        assert!(
            store.zombie_cancelled_for_non2xx(&sent_cid).is_some(),
            "a retransmitted 487 must still be ACKable"
        );

        // ...and it must not have consumed the glare path's first-2xx flag: a
        // 487 followed by a raced 2xx (both are possible on a forked downstream)
        // must still produce ACK + BYE for the 2xx.
        let (_leg, first_2xx) = store
            .zombie_cancelled_for_2xx(&sent_cid)
            .expect("the glare entry survives a 487 lookup");
        assert!(
            first_2xx,
            "ACKing a 487 must not consume the BYE the glare 2xx path owes"
        );
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

    fn originated_refer(call_id: &str) -> OriginatedRefer {
        OriginatedRefer {
            call_id: call_id.to_string(),
            on_a_leg: true,
            target_uri: "sip:caller@198.51.100.10:5060".to_string(),
            refer_to: crate::sip::headers::refer::ReferTo {
                uri: "sip:agent@pbx.example.com".to_string(),
                replaces: None,
            },
            auth_retries: 0,
        }
    }

    #[test]
    fn originated_refer_is_matched_by_branch_and_taken_once() {
        // A REFER siphon originates carries a branch belonging to no leg, so it
        // is tracked separately; its final response ends the transaction and
        // must consume the entry (a non-INVITE transaction has exactly one).
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.register_originated_refer("z9hG4bK-refer-1", originated_refer(&call_id));

        assert!(store.lookup_originated_refer("z9hG4bK-refer-1").is_some());
        let taken = store.take_originated_refer("z9hG4bK-refer-1").unwrap();
        assert_eq!(taken.call_id, call_id);
        assert!(taken.on_a_leg);
        assert_eq!(taken.refer_to.uri, "sip:agent@pbx.example.com");
        // Gone: a retransmitted final must not drive a second retry.
        assert!(store.take_originated_refer("z9hG4bK-refer-1").is_none());
    }

    #[test]
    fn originated_refer_does_not_leak_into_the_leg_branch_index() {
        // Registering it in `by_branch` would send the REFER's 401 down the
        // INVITE/B-leg response path, which ACKs a non-2xx — wrong for a
        // non-INVITE transaction (RFC 3261 §17.1.2).
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.register_originated_refer("z9hG4bK-refer-2", originated_refer(&call_id));
        assert!(store.call_id_for_branch("z9hG4bK-refer-2").is_none());
    }

    #[test]
    fn originated_refer_is_dropped_when_its_call_goes_away() {
        // A call that is gone cannot be transferred; leaving the entry would
        // leak one per abandoned transfer.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.register_originated_refer("z9hG4bK-refer-3", originated_refer(&call_id));
        store.remove_call(&call_id);
        assert!(store.lookup_originated_refer("z9hG4bK-refer-3").is_none());
    }

    #[test]
    fn registry_basic() {
        let reg = LegRegistry::new();
        reg.register_call_id("call-1@host", "internal-1");
        reg.register_branch("z9hG4bK-test", "internal-1");

        assert_eq!(
            reg.lookup_call_id("call-1@host"),
            Some("internal-1".to_string())
        );
        assert_eq!(
            reg.lookup_branch("z9hG4bK-test"),
            Some("internal-1".to_string())
        );
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
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: response,
                source: test_transport(),
            })
            .await
            .unwrap();

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
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: response,
                source: test_transport(),
            })
            .await
            .unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Failed {
                leg_id: id,
                status_code,
                ..
            } => {
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
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: response,
                source: test_transport(),
            })
            .await
            .unwrap();

        let event = call_rx.recv().await.unwrap();
        match event {
            CallEvent::Provisional {
                leg_id: id,
                status_code,
                ..
            } => {
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
            .request(
                Method::Bye,
                crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
            )
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("2 BYE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: bye,
                source: test_transport(),
            })
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
            .await
            .unwrap()
            .unwrap();
        match event {
            CallEvent::Bye {
                leg_id: id,
                from_side,
                ..
            } => {
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
            .request(
                Method::Invite,
                crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
            )
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-reinv".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("2 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: reinvite,
                source: test_transport(),
            })
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
            .await
            .unwrap()
            .unwrap();
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
        let pai = "\"Outbound Call\" <sip:alice@10.0.0.5>";
        let result = rewrite_uri_host(pai, "203.0.113.5");
        assert_eq!(result, "\"Outbound Call\" <sip:alice@203.0.113.5>");
    }

    // --- rewrite_uri_authority tests ---

    #[test]
    fn rewrite_uri_authority_replaces_host_and_port() {
        // Regression: the original To carried siphon's inbound port (:5061)
        // leaked from the A-leg.  Topology-hiding the To to a dial target that
        // itself carries a port must replace host AND port — replacing host
        // only left the old port and produced `host:5060:5061` (double port),
        // which the SBC rejected as 400 Wrong URI.
        let to = "<sip:bob@pcscf.example.com:5061;user=phone>";
        let result = rewrite_uri_authority(to, "trunk.example.com:5060");
        assert_eq!(result, "<sip:bob@trunk.example.com:5060;user=phone>");
        // No double port anywhere in the result.
        assert!(!result.contains(":5060:"));
        assert!(!result.contains("5060:5061"));
    }

    #[test]
    fn rewrite_uri_authority_drops_old_port_when_target_has_none() {
        let to = "<sip:bob@10.0.0.1:5061;user=phone>";
        let result = rewrite_uri_authority(to, "trunk.example.com");
        assert_eq!(result, "<sip:bob@trunk.example.com;user=phone>");
    }

    #[test]
    fn rewrite_uri_authority_no_original_port() {
        let to = "<sip:bob@old.example.com;user=phone>";
        let result = rewrite_uri_authority(to, "trunk.example.com:5060");
        assert_eq!(result, "<sip:bob@trunk.example.com:5060;user=phone>");
    }

    #[test]
    fn rewrite_uri_authority_no_params_no_port() {
        let to = "<sip:bob@old.example.com>";
        let result = rewrite_uri_authority(to, "trunk.example.com:5060");
        assert_eq!(result, "<sip:bob@trunk.example.com:5060>");
    }

    #[test]
    fn rewrite_uri_authority_display_name() {
        let to = "\"Alice\" <sip:alice@old.example.net:5061;user=phone>";
        let result = rewrite_uri_authority(to, "gw.example.net:5060");
        assert_eq!(
            result,
            "\"Alice\" <sip:alice@gw.example.net:5060;user=phone>"
        );
    }

    #[test]
    fn rewrite_uri_authority_no_at_sign() {
        let to = "<sip:host.a:5060>";
        let result = rewrite_uri_authority(to, "gw.b:5060");
        // No @ sign — returned unchanged.
        assert_eq!(result, to);
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
        assert_eq!(ensure_tag(to, Some("abc")), "<sip:bob@example.com>;tag=abc");
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
            .request(
                Method::Refer,
                crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
            )
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-refer".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("3 REFER".to_string())
            .header("Refer-To", "<sip:carol@chicago.com>".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: refer,
                source: test_transport(),
            })
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
            .await
            .unwrap()
            .unwrap();
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
            .request(
                Method::Options,
                crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
            )
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-opts".to_string())
            .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
            .to("<sip:alice@atlanta.com>;tag=abc".to_string())
            .call_id("b2b-bleg0".to_string())
            .cseq("4 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handle
            .tx
            .send(LegMessage::SipInbound {
                message: options,
                source: test_transport(),
            })
            .await
            .unwrap();

        // Should timeout — no event expected
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), call_rx.recv()).await;
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
            .build()
            .unwrap();
        handles[0]
            .tx
            .send(LegMessage::SipInbound {
                message: ringing,
                source: test_transport(),
            })
            .await
            .unwrap();

        // Leg 1: 486 Busy
        let busy = crate::sip::builder::SipMessageBuilder::new()
            .response(486, "Busy Here".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f1".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=b1".to_string())
            .call_id("b2b-bleg1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handles[1]
            .tx
            .send(LegMessage::SipInbound {
                message: busy,
                source: test_transport(),
            })
            .await
            .unwrap();

        // Leg 2: 200 OK
        let ok = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f2".to_string())
            .from("<sip:alice@atlanta.com>;tag=abc".to_string())
            .to("<sip:bob@biloxi.com>;tag=b2".to_string())
            .call_id("b2b-bleg2".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        handles[2]
            .tx
            .send(LegMessage::SipInbound {
                message: ok,
                source: test_transport(),
            })
            .await
            .unwrap();

        // Collect all 3 events — order may vary
        let mut events = Vec::new();
        for _ in 0..3 {
            let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
                .await
                .unwrap()
                .unwrap();
            events.push(event);
        }

        // Verify all 3 leg_ids are present
        let event_leg_ids: std::collections::HashSet<String> = events
            .iter()
            .map(|e| match e {
                CallEvent::Provisional { leg_id, .. } => leg_id.0.clone(),
                CallEvent::Answered { leg_id, .. } => leg_id.0.clone(),
                CallEvent::Failed { leg_id, .. } => leg_id.0.clone(),
                CallEvent::Terminated { leg_id, .. } => leg_id.0.clone(),
                CallEvent::Bye { leg_id, .. } => leg_id.0.clone(),
                CallEvent::ReInvite { leg_id, .. } => leg_id.0.clone(),
                CallEvent::Refer { leg_id, .. } => leg_id.0.clone(),
            })
            .collect();

        for id in &leg_ids {
            assert!(
                event_leg_ids.contains(&id.0),
                "missing event for leg {}",
                id
            );
        }

        // Verify event types
        assert!(events.iter().any(|e| matches!(
            e,
            CallEvent::Provisional {
                status_code: 180,
                ..
            }
        )));
        assert!(events.iter().any(|e| matches!(
            e,
            CallEvent::Failed {
                status_code: 486,
                ..
            }
        )));
        assert!(events
            .iter()
            .any(|e| matches!(e, CallEvent::Answered { .. })));

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
            tokio::time::timeout(std::time::Duration::from_secs(2), join)
                .await
                .expect("actor did not terminate")
                .unwrap();
        }
    }

    // --- Recently-terminated Call-IDs (post-teardown 481) ---

    #[test]
    fn teardown_remembers_every_leg_call_id() {
        // Hang-up glare: whichever peer's BYE loses the race must still be
        // answerable, and on a B2BUA that peer may be on either side, so both
        // the A-leg and every B-leg Call-ID has to be remembered.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));
        store.add_b_leg(&call_id, make_b_leg(1));

        assert!(!store.is_recently_terminated("call-1@10.0.0.1"));

        store.remove_call(&call_id);

        assert!(store.is_recently_terminated("call-1@10.0.0.1"));
        assert!(store.is_recently_terminated("b2b-bleg0"));
        assert!(store.is_recently_terminated("b2b-bleg1"));
        // A Call-ID this node never saw stays unknown — the dispatcher leaves
        // those to the script (a proxy loose-routes dialogs it doesn't track).
        assert!(!store.is_recently_terminated("stranger@10.0.0.9"));
        assert!(!store.is_recently_terminated(""));
    }

    #[test]
    fn live_call_is_never_remembered_as_terminated() {
        // Guards the dispatcher's ordering: a call that is up must not be able
        // to answer 481 to its own in-dialog requests.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.add_b_leg(&call_id, make_b_leg(0));

        assert!(!store.is_recently_terminated("call-1@10.0.0.1"));
        assert!(!store.is_recently_terminated("b2b-bleg0"));
    }

    #[test]
    fn legs_sharing_a_call_id_are_remembered_once() {
        // With preserve_call_id — and for the dispatcher's `reinvite:` tracking
        // pseudo-legs — a B-leg carries the A-leg's Call-ID. One membership entry
        // covers both.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        let mut b_leg = make_b_leg(0);
        b_leg.dialog.call_id = "call-1@10.0.0.1".to_string();
        store.add_b_leg(&call_id, b_leg);

        store.remove_call(&call_id);

        assert!(store.is_recently_terminated("call-1@10.0.0.1"));
        assert_eq!(store.terminated.len(), 1);
    }

    #[test]
    fn re_terminating_a_reused_call_id_keeps_it_remembered() {
        // Regression: a peer that reuses one Call-ID across calls used to LOSE its
        // 481. The second teardown found the Call-ID already present and pushed no
        // fresh entry, so eviction aged out the first call's entry and removed the
        // Call-ID that had just been remembered again. The stamp is a generation:
        // an expiring entry may only remove the Call-ID if it is still current.
        let terminated = DashMap::new();
        let mut order = VecDeque::new();
        let base = Instant::now();
        let refreshed = base + Duration::from_secs(60);
        // Remembered at `base`, then again at `refreshed`.
        terminated.insert("reused@10.0.0.1".to_string(), refreshed);
        order.push_back(("reused@10.0.0.1".to_string(), base));
        order.push_back(("reused@10.0.0.1".to_string(), refreshed));

        // The first entry is well past the TTL; the second is not.
        CallActorStore::evict_terminated(
            &terminated,
            &mut order,
            base + Duration::from_secs(40),
            TERMINATED_CALL_TTL,
            TERMINATED_CALL_CAPACITY,
        );

        assert!(terminated.contains_key("reused@10.0.0.1"));
        assert_eq!(order.len(), 1);
    }

    #[test]
    fn second_teardown_of_the_same_call_id_still_remembered() {
        // The store-level shape of the regression above: tear down, reuse the
        // Call-ID for another call, tear that down too. Still answerable.
        let store = CallActorStore::new();
        let first = store.create_call(make_a_leg());
        store.remove_call(&first);
        let second = store.create_call(make_a_leg());
        store.remove_call(&second);

        assert!(store.is_recently_terminated("call-1@10.0.0.1"));
        assert_eq!(store.terminated.len(), 1);
    }

    #[test]
    fn terminated_evicts_by_age() {
        // Past the TTL the peer's own transaction has timed out, so the entry
        // has nothing left to answer. `now` is moved forward rather than slept.
        let store = CallActorStore::new();
        let call_id = store.create_call(make_a_leg());
        store.remove_call(&call_id);
        assert!(store.is_recently_terminated("call-1@10.0.0.1"));

        let mut order = store.terminated_order.lock().unwrap();
        CallActorStore::evict_terminated(
            &store.terminated,
            &mut order,
            Instant::now() + Duration::from_secs(40),
            TERMINATED_CALL_TTL,
            TERMINATED_CALL_CAPACITY,
        );
        drop(order);

        assert!(!store.is_recently_terminated("call-1@10.0.0.1"));
        assert_eq!(store.terminated_order.lock().unwrap().len(), 0);
    }

    #[test]
    fn terminated_evicts_by_capacity_oldest_first() {
        // The cap is what keeps a 40k-cps run from holding 32 s of Call-IDs.
        let terminated = DashMap::new();
        let mut order = VecDeque::new();
        let base = Instant::now();
        for index in 0..5 {
            let stamp = base + Duration::from_millis(index);
            terminated.insert(format!("cid-{index}"), stamp);
            order.push_back((format!("cid-{index}"), stamp));
        }

        CallActorStore::evict_terminated(&terminated, &mut order, base, TERMINATED_CALL_TTL, 2);

        // Newest two survive, in order.
        assert_eq!(order.len(), 2);
        assert!(!terminated.contains_key("cid-0"));
        assert!(!terminated.contains_key("cid-1"));
        assert!(!terminated.contains_key("cid-2"));
        assert!(terminated.contains_key("cid-3"));
        assert!(terminated.contains_key("cid-4"));
    }
}

#[cfg(test)]
mod originate_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn transport() -> TransportInfo {
        TransportInfo {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        }
    }

    fn originating_leg() -> Leg {
        Leg::new_originating_leg(
            "orig-call@siphon.invalid".to_string(),
            "sip-from-tag".to_string(),
            "sip:+14035551212@carrier.example".to_string(),
            "z9hG4bK-orig1".to_string(),
            transport(),
        )
    }

    #[test]
    fn originating_leg_is_an_a_leg_with_an_outbound_dialog() {
        let leg = originating_leg();
        assert_eq!(leg.side, LegSide::A);
        // Outbound dialog: our tag is the local (From) tag, the remote tag is
        // still unknown, and the target URI is the R-URI we INVITE.
        assert_eq!(leg.dialog.local_tag, "sip-from-tag");
        assert!(leg.dialog.remote_tag.is_none());
        assert_eq!(
            leg.dialog.target_uri.as_deref(),
            Some("sip:+14035551212@carrier.example")
        );
        assert_eq!(leg.dialog.local_cseq, 1);
        assert!(!leg.is_tracking_leg());
    }

    #[test]
    fn a_fresh_call_is_not_originated() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        assert!(!store.is_originated(&call_id));
    }

    /// A call siphon placed itself carries its pending INVITE on the A-leg, so
    /// the B-leg capture loop finds nothing — without the A-leg arm the `487
    /// Request Terminated` its CANCEL draws (RFC 3261 §9.1) is dropped as an
    /// unknown branch, unACKed, and the peer retransmits to Timer H (§17.2.1).
    #[test]
    fn cancelled_originate_is_zombified_with_its_invite_ruri_for_the_487_ack() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        store.mark_originated(&call_id, "z9hG4bK-orig1");

        let sip_call_id = "orig-call@siphon.invalid".to_string();
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("carrier.example".to_string())
                    .with_user("+14035551212".to_string()),
            )
            .via("SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-orig1".to_string())
            .from("<sip:siphon@198.51.100.10>;tag=sip-from-tag".to_string())
            .to("<sip:+14035551212@carrier.example>".to_string())
            .call_id(sip_call_id.clone())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        store.set_a_leg_invite(&call_id, Arc::new(Mutex::new(invite)));

        assert!(
            store.remove_call_after_cancel(&call_id),
            "an originated call's pending A-leg must be captured"
        );

        let (leg, ruri) = store
            .zombie_cancelled_for_non2xx(&sip_call_id)
            .expect("the CANCELled originate must still resolve for its 487");
        // RFC 3261 §17.1.1.3 — the ACK rides the INVITE's own branch and
        // Request-URI.
        assert_eq!(leg.branch, "z9hG4bK-orig1");
        assert_eq!(ruri.as_deref(), Some("sip:+14035551212@carrier.example"));
    }

    #[test]
    fn mark_originated_flags_the_call_and_indexes_the_branch() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        store.mark_originated(&call_id, "z9hG4bK-orig1");

        assert!(store.is_originated(&call_id));
        assert_eq!(
            store.lookup_originated_call("z9hG4bK-orig1").as_deref(),
            Some(call_id.as_str())
        );
        assert!(store
            .lookup_originated_call("z9hG4bK-someone-else")
            .is_none());
    }

    #[test]
    fn removing_the_call_drains_the_originate_branch_index() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        store.mark_originated(&call_id, "z9hG4bK-orig1");
        assert_eq!(store.registry.originated_call_count(), 1);

        store.remove_call(&call_id);
        assert_eq!(store.registry.originated_call_count(), 0);
        assert!(store.lookup_originated_call("z9hG4bK-orig1").is_none());
    }

    /// Steady-state leak guard for the originate branch index: a batch of
    /// complete place-then-tear-down cycles must return every store to the
    /// length it started at.
    #[test]
    fn originate_cycles_drain_every_store_to_baseline() {
        let store = CallActorStore::new();
        let baseline = (store.count(), store.registry.originated_call_count());

        for index in 0..200 {
            let leg = Leg::new_originating_leg(
                format!("orig-{index}@siphon.invalid"),
                format!("tag-{index}"),
                "sip:+14035551212@carrier.example".to_string(),
                format!("z9hG4bK-orig-{index}"),
                transport(),
            );
            let call_id = store.create_call(leg);
            store.mark_originated(&call_id, &format!("z9hG4bK-orig-{index}"));
            store.remove_call(&call_id);
        }

        assert_eq!(
            (store.count(), store.registry.originated_call_count()),
            baseline,
            "originate must not retain per-call state after teardown"
        );
    }

    #[test]
    fn an_originated_call_routes_its_own_in_dialog_requests_to_the_a_leg() {
        // RFC 3261 §12: the far end's BYE carries our dialog Call-ID, and its
        // From-tag is the tag it assigned (our `remote_tag`). A single-leg
        // originated call must resolve that to the A-leg, never to "no dialog".
        let mut actor = CallActor::new(originating_leg());
        actor.a_leg.dialog.remote_tag = Some("peer-tag".to_string());
        assert_eq!(
            actor.request_direction("orig-call@siphon.invalid", Some("peer-tag")),
            Some(LegSide::A)
        );
        assert_eq!(
            actor.request_direction("some-other-call@elsewhere", Some("peer-tag")),
            None
        );
    }
}
