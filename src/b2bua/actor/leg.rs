//! A single SIP dialog leg and the routing table over legs.
//!
//! [`Leg`] owns its [`Dialog`] (Call-ID, tags, CSeq) and [`TransportInfo`]
//! independently of every other leg, which is what lets a forked call hold
//! several B-legs with unrelated dialog state. [`LegRegistry`] is the
//! SIP-level routing table (Call-ID, Via branch → internal call id) the
//! dispatcher consults to get an inbound message to the right call.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use dashmap::DashMap;

use crate::sip::message::SipMessage;
use crate::transport::{ConnectionId, Transport};

use super::*;

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
