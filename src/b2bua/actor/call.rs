//! The per-call supervisor: [`CallActor`] and the state it holds.
//!
//! A call owns one A-leg and any number of B-legs, tracks per-leg status,
//! picks a winner on fork, and carries everything that outlives a single leg —
//! transfer subscriptions, `Replaces` bookkeeping, the LCR route sequence, and
//! the session timer.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::sip::best_response::ResponseRank;
use crate::sip::message::SipMessage;

use super::*;

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

/// A leg replacement in flight on a B2BUA call — of which a REFER-driven one
/// (RFC 3515) also carries the implicit subscription siphon owns for it.
///
/// Every replacement records one of these: a new leg has been dialed, and when
/// it answers it is promoted into the surviving pair and the leg it replaces is
/// BYE'd. `origin` says whether a referrer is owed sipfrag NOTIFYs along the
/// way — see [`ReplacementOrigin`](crate::b2bua::transfer::ReplacementOrigin).
///
/// Three roles:
/// - **notifier** (`siphon_notifies == true`, `origin == Refer`) — the
///   siphon-terminated inbound path: a UA sent siphon a REFER, siphon answered
///   `202`, and now sends the `message/sipfrag` NOTIFY progress to that referrer
///   as the new leg it dialed makes progress.
/// - **siphon-initiated** (`siphon_notifies == true`,
///   `origin == SiphonInitiated`) — `b2bua.replace_peer()`: the same dial /
///   promote / BYE round, decided by a script or a controller, with no REFER and
///   therefore nobody to notify.
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
    /// What asked for this replacement, and therefore whether a referrer is
    /// owed sipfrag NOTIFYs. Meaningful only in the notifier role; the
    /// subscriber role (`call.refer()`) is always `Refer`.
    pub origin: crate::b2bua::transfer::ReplacementOrigin,
    /// The subscription `id` token — the CSeq number of the REFER that created
    /// it (RFC 3515 §2.4.4) — surfaced as `Event: refer;id=<n>` to disambiguate
    /// concurrent transfers on one dialog. Meaningless when `origin` is
    /// `SiphonInitiated`: there is no REFER, so there is no CSeq to echo and no
    /// subscription to disambiguate, and nothing reads it on that path.
    pub event_id: u32,
    /// Next CSeq for a siphon-originated NOTIFY on this subscription (notifier
    /// role only).
    pub notify_cseq: u32,
    /// Current transfer progress (drives the sipfrag body and teardown).
    pub state: crate::b2bua::transfer::TransferState,
    /// For a siphon-terminated inbound transfer: the dialog Call-ID of the leg
    /// siphon dialed to the transfer target. The response path matches an
    /// answering b_leg against this exact Call-ID (not just "a non-winner leg")
    /// so an unrelated leg dialed while a transfer is pending can't be mistaken
    /// for the transfer target. `None` for the subscriber (outbound) role.
    pub target_leg_call_id: Option<String>,
    /// True once the dialog of the leg being replaced ended while the
    /// replacement was still in flight — for a REFER, the referrer sent a BYE
    /// after siphon accepted it but before the dialed target resolved.
    ///
    /// Two consequences, and they are separate:
    /// - **No BYE at completion.** The leg being replaced already left, so
    ///   there is nothing to release. This holds for both origins.
    /// - **No NOTIFY.** RFC 3515 §2.4.4: the implicit refer subscription lives
    ///   in the dialog the REFER arrived on, so once that dialog ends no
    ///   further NOTIFY can be delivered (a late one draws a 481). This is
    ///   about the *subscription*, and applies only when `origin == Refer` —
    ///   a `SiphonInitiated` replacement has no subscription to end.
    ///
    /// The replacement itself continues either way: RFC 5589 §7 has the
    /// transferor free to end its dialog as soon as the REFER is accepted, and
    /// the surviving party ↔ target call is what the transfer exists to create.
    /// Notifier role only.
    pub referrer_gone: bool,
    /// When to give up on the dialed target, for a notifier-role replacement.
    ///
    /// The replacement runs on an **answered** call, and the answer-timeout
    /// sweep ([`take_timed_out_calls`](CallActorStore::take_timed_out_calls))
    /// deliberately looks only at `Calling`/`Ringing` calls — so without a
    /// deadline of its own a target that never sends a final response leaves
    /// this subscription armed forever, the response path still matching on
    /// `target_leg_call_id`, and the surviving party bridged to nobody. `None`
    /// keeps the pre-deadline behaviour (wait indefinitely).
    pub deadline: Option<std::time::Instant>,
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
    /// Whether the in-flight attempt has shown progress: a 101-199 on its own
    /// B-leg. Cleared when the next carrier is taken, so one carrier's progress
    /// never keeps the carrier after it. See
    /// [`CallActor::record_route_progress`].
    pub active_progressed: bool,
    /// Where the in-flight attempt's legs start in [`CallActor::b_legs`]; the
    /// legs before it belong to carriers already tried. Taken with the carrier,
    /// before its INVITE exists, so a late provisional from an earlier carrier
    /// never reads as this one's progress.
    pub active_legs_start: usize,
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
    /// Whether this carrier's INVITE actually reached the transport.
    ///
    /// `false` means siphon never sent it — the carrier's gateway group was
    /// unknown or entirely down, or its destination would not resolve — so
    /// `status` is siphon's own verdict on the route and **not** something the
    /// carrier said. Without this the two are indistinguishable, and a local
    /// DNS or gateway problem reads as a carrier fault in `route_attempts`, in
    /// the CDR's `lcr_attempts`, and in `@b2bua.on_route_failure` — the data an
    /// operator trends a carrier on, and takes to that carrier.
    pub dialed: bool,
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
    pub transfer: Option<crate::b2bua::transfer::TransferContext>,
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
    /// The winning B-leg's ACK when its INVITE went out without an offer, so the
    /// 2xx carried the offer and the ACK has to carry the answer (RFC 3261
    /// §13.2.2.4, RFC 3264 §4). Held until the caller's ACK brings that answer,
    /// then kept as sent so every retransmission of the 2xx gets it again. `None`
    /// for a call whose INVITE carried an offer: that 2xx is ACKed on arrival.
    pub delayed_offer_ack: Option<DelayedOfferAck>,
    /// Set by the first teardown to take this call over
    /// ([`CallActorStore::claim_teardown`]): only that teardown sends BYEs and
    /// removes the call, so two racing each other cannot BYE a leg twice.
    pub teardown_claimed: bool,
    /// Resolved header policy for this call (preset + per-call deltas) — set
    /// when the script calls `call.dial(header_policy=…)`.  When `None`, the
    /// dispatcher falls back to the configured `b2bua.default_header_policy`.
    pub resolved_header_policy: Option<std::sync::Arc<crate::b2bua::header_policy::ResolvedPolicy>>,
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
    /// When this call was answered, stamped by
    /// [`transition_to`](Self::transition_to) on the first transition to
    /// [`CallState::Answered`] and never moved afterwards (a re-INVITE or a leg
    /// replacement re-enters `Answered` but does not restart the call).
    /// `None` until then. The anchor [`max_duration_secs`] measures
    /// from — the ring is already bounded by [`answer_deadline`], so a cap on
    /// the whole call would otherwise vary with how long it rang.
    ///
    /// [`max_duration_secs`]: Self::max_duration_secs
    /// [`answer_deadline`]: Self::answer_deadline
    pub answered_at: Option<std::time::Instant>,
    /// Ceiling on how long this call may stay answered, in seconds
    /// (`call.dial(max_duration=…)` and friends). Once
    /// `answered_at + max_duration_secs` passes, the framework BYEs both legs
    /// through the ordinary teardown.
    ///
    /// `Some(0)` is an explicit opt-out for this call, which is how a script
    /// escapes a configured `b2bua.max_call_duration_secs`; `None` inherits
    /// that configured default (itself usually absent, i.e. uncapped).
    pub max_duration_secs: Option<u32>,
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
    /// Set while a controller-issued `dial` owns this call's outcome.
    ///
    /// A `dial` rings B-legs while the caller stays unanswered and parked, so
    /// the controller — not siphon — decides what happens when nobody answers:
    /// dial elsewhere, answer into voicemail, reject with its own code. Without
    /// this the B-leg failure path would forward the error to the caller and
    /// tear the call down, which is the opposite of keeping it.
    ///
    /// Cleared the moment the outcome is decided: a 2xx makes it an ordinary
    /// two-leg call, and a reported failure hands the decision back.
    pub control_dial: bool,
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
    /// The media anchor an early-media response opened on the A-leg, and the
    /// SDP answer that response carried. The 2xx that follows repeats that
    /// answer (RFC 3264 §4) instead of anchoring again. `None` until a
    /// controller sends an anchored `progress`.
    pub early_media_anchor: Option<EarlyMediaAnchor>,
    /// This call's half of a bridge with another call this process owns, set
    /// while a `bridge` is forming and for as long as it holds. Mirrored on the
    /// peer's actor, so either side's teardown finds the other
    /// ([`crate::b2bua::bridge`]).
    pub bridge: Option<crate::b2bua::bridge::BridgeContext>,
    /// True while `call.fork()` is still putting its branches on the wire.
    ///
    /// Branches go out one at a time, and one can fail before the next has even
    /// been added, so a fork settled on the branches it could see would fail a
    /// call whose other branches were about to ring. Failures recorded meanwhile
    /// are held until [`finish_fork_dispatch`](Self::finish_fork_dispatch).
    pub fork_dispatching: bool,
    /// The best final failure this call's branches have produced so far, which
    /// is what the A-leg is sent once no branch is left ringing (RFC 3261 §16.7).
    pub fork_best_failure: Option<BranchFailure>,
    /// How many times `@b2bua.on_failure` has routed this call again. Capped, so
    /// a handler that keeps re-dialling a target that keeps failing cannot hold
    /// the call, or the thread, forever.
    pub failure_reroutes: u32,
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
/// Early media anchored on the media engine: the SDP answer siphon already sent
/// the caller in an 18x, kept so the 2xx can repeat it.
///
/// Holds the SDP text rather than engine flags, like [`OriginateAnchor`], so the
/// actor layer stays free of media types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EarlyMediaAnchor {
    /// The engine's SDP answer, exactly as the early response carried it.
    pub answer_sdp: String,
    /// The media profile the anchor was made with.
    pub profile: String,
}
impl CallActor {
    /// Whether one of this call's legs carries the dialog `sip_call_id`. A
    /// transfer or a takeover can release a party from the call, and move one to
    /// another slot, while the call goes on.
    pub fn carries_dialog(&self, sip_call_id: &str) -> bool {
        self.a_leg.dialog.call_id == sip_call_id
            || self
                .b_legs
                .iter()
                .any(|leg| leg.dialog.call_id == sip_call_id)
    }

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
            delayed_offer_ack: None,
            teardown_claimed: false,
            resolved_header_policy: None,
            a_leg_supports_100rel: false,
            auth_retry_count: 0,
            answer_deadline: None,
            answered_at: None,
            max_duration_secs: None,
            auth_passthrough: false,
            route_sequence: None,
            control_app: None,
            control_dial: false,
            on_control_loss: None,
            handoff_pending: false,
            originated: false,
            originate_anchor: None,
            early_media_anchor: None,
            bridge: None,
            fork_dispatching: false,
            fork_best_failure: None,
            failure_reroutes: 0,
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
        let legs_so_far = self.b_legs.len();
        let sequence = self.route_sequence.as_mut()?;
        let route = sequence.pending.pop_front()?;
        sequence.active = Some(route.clone());
        sequence.active_since = Some(std::time::Instant::now());
        sequence.active_progressed = false;
        sequence.active_legs_start = legs_so_far;
        Some(route)
    }

    /// Note a provisional `status_code` on the B-leg `branch` of a sequential
    /// failover call. Returns whether it was the in-flight attempt's first
    /// progress.
    ///
    /// Progress is a 101-199. RFC 3261 §16.7 step 2 resets a proxy's Timer C on
    /// any provisional but a 100, which is hop-by-hop and says nothing about the
    /// far end. It counts only on a still-pending leg of the attempt in flight,
    /// so a late provisional from a carrier already tried, CANCELled or not,
    /// cannot mark the carrier after it.
    ///
    /// The first one moves the answer deadline to the later of the route's own
    /// and the sequence's ring bound, both counted from the dial, so progress
    /// never shortens a ring. A ring bound of 0 is no bound, as `timeout=0` is
    /// for a dial; a deadline that was never armed stays unarmed. A route with
    /// `reroute_after_progress` is recorded as having shown progress but keeps
    /// its own deadline, and [`route_kept_by_progress`](Self::route_kept_by_progress)
    /// stays false for it.
    pub fn record_route_progress(&mut self, branch: &str, status_code: u16) -> bool {
        if !(101..=199).contains(&status_code) {
            return false;
        }
        let Some(index) = self.b_legs.iter().position(|leg| leg.branch == branch) else {
            return false;
        };
        if !self.is_pending_branch(index) {
            return false;
        }
        let answer_deadline = self.answer_deadline;
        let Some(sequence) = self.route_sequence.as_mut() else {
            return false;
        };
        if sequence.active_progressed || index < sequence.active_legs_start {
            return false;
        }
        let Some(reroute_after_progress) = sequence
            .active
            .as_ref()
            .map(|route| route.reroute_after_progress)
        else {
            return false;
        };
        sequence.active_progressed = true;
        if reroute_after_progress {
            return true;
        }
        let ring_bound = sequence.default_timeout;
        if let (Some(deadline), Some(dialled)) = (answer_deadline, sequence.active_since) {
            self.answer_deadline = match ring_bound {
                0 => None,
                seconds => {
                    Some(deadline.max(dialled + std::time::Duration::from_secs(u64::from(seconds))))
                }
            };
        }
        true
    }

    /// Whether the carrier in flight has shown progress and so keeps the call
    /// past its ring timeout: when its deadline fires the call fails rather than
    /// advancing. See [`record_route_progress`](Self::record_route_progress).
    pub fn route_kept_by_progress(&self) -> bool {
        self.route_sequence.as_ref().is_some_and(|sequence| {
            sequence.active_progressed
                && sequence
                    .active
                    .as_ref()
                    .is_some_and(|route| !route.reroute_after_progress)
        })
    }

    /// Whether the carrier in flight has sent a 101-199, whatever its route does
    /// with it. Unlike [`route_kept_by_progress`](Self::route_kept_by_progress)
    /// this holds for a route with `reroute_after_progress` too: it says the
    /// carrier got as far as the callee, which is what decides the status a
    /// call fails with when that carrier's ring timeout ends the sequence.
    pub fn route_attempt_progressed(&self) -> bool {
        self.route_sequence
            .as_ref()
            .is_some_and(|sequence| sequence.active_progressed)
    }

    /// Settle the B-leg at `index` of a sequential failover call on its final
    /// failure `status_code`, before the sequence moves on. Returns whether the
    /// leg was still waiting for one: `false` for a leg already settled, failed
    /// or CANCELled, which makes the response a retransmission or a straggler.
    ///
    /// A parallel fork settles a branch through
    /// [`record_branch_failure`](Self::record_branch_failure), which also ranks
    /// it against its siblings. A sequence ranks its carriers on its attempt
    /// list instead, so this only marks the leg failed. Without it a carrier
    /// that had failed and been ACKed stayed pending, and every later sweep of
    /// pending branches (the next carrier's ring timeout, a caller CANCEL, an
    /// answer, a re-route from `@b2bua.on_failure`) sent it a CANCEL, which
    /// RFC 3261 §9.1 says SHOULD NOT follow a final response.
    pub fn settle_route_branch(&mut self, index: usize, status_code: u16) -> bool {
        if !self.is_pending_branch(index) {
            return false;
        }
        if let Some(status) = self.b_leg_status.get_mut(index) {
            *status = BLegStatus::Failed(status_code);
        }
        true
    }

    /// Record a failed attempt against the carrier that was in flight. No-op for
    /// a non-sequential call.
    ///
    /// Returns the attempt, so the caller can log it and hand it to
    /// `@b2bua.on_route_failure` without re-reading the actor.
    pub fn record_route_failure(&mut self, status_code: u16) -> Option<RouteAttempt> {
        self.record_route_attempt(status_code, true)
    }

    /// Record a carrier that was burned **without ever being dialled** — its
    /// gateway group was unknown or entirely down, or its destination would not
    /// resolve, so no INVITE left the box.
    ///
    /// It still belongs on the attempt list: the sequence consumed that carrier
    /// and the caller's call took the consequences. `dialed: false` is what
    /// keeps it from reading as the carrier's own answer.
    pub fn record_route_undialed(&mut self, status_code: u16) -> Option<RouteAttempt> {
        self.record_route_attempt(status_code, false)
    }

    fn record_route_attempt(&mut self, status_code: u16, dialed: bool) -> Option<RouteAttempt> {
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
            dialed,
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

    /// The best failure across the attempts so far, ranked per RFC 3261 §16.7
    /// step 6 ([`crate::sip::best_response`]). Derived from
    /// [`RouteSequenceState::attempts`] rather than accumulated, so it and the
    /// per-attempt record can never disagree.
    pub fn best_route_error(&self) -> Option<u16> {
        crate::sip::best_response::best_status(
            self.route_attempts().iter().map(|attempt| attempt.status),
        )
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
            // The retry continues this leg's SDP session. The INVITE it re-sends
            // carries the superseded leg's `o=`, and every later offer on the
            // dialog has to present that session id with a greater version
            // (RFC 3264 §8), so the fresh identity the retry leg was built with
            // gives way to the one the callee has already seen.
            let mut leg = leg;
            let superseded = &self.b_legs[index].dialog;
            leg.dialog.sdp_session_id = superseded.sdp_session_id;
            leg.dialog.sdp_version = superseded.sdp_version;
            // The retry re-sends the superseded INVITE's offer, so the session
            // description in force on the dialog is the same one.
            leg.dialog.last_sent_sdp = superseded.last_sent_sdp.clone();
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

    /// Move this call to `state`, stamping [`answered_at`](Self::answered_at)
    /// on the **first** transition to [`CallState::Answered`].
    ///
    /// Every state change goes through here so the stamp cannot be missed:
    /// answering is reached from three unrelated directions — a winning B-leg
    /// 2xx ([`set_winner`](Self::set_winner)), a promoted leg replacement, and
    /// the store's [`set_state`](CallActorStore::set_state) for the UAS-mode
    /// `call.answer()` and an originate's 2xx — and a cap that silently never
    /// fires because one of them wrote the field directly is worse than no cap
    /// at all. Only the first transition counts, so a re-INVITE or a leg
    /// replacement re-entering `Answered` cannot push the deadline back out.
    pub fn transition_to(&mut self, state: CallState) {
        if state == CallState::Answered && self.answered_at.is_none() {
            self.answered_at = Some(std::time::Instant::now());
        }
        self.state = state;
    }

    /// Set the winner and update call state.
    pub fn set_winner(&mut self, index: usize) {
        self.winner = Some(index);
        self.transition_to(CallState::Answered);
        if index < self.b_leg_status.len() {
            self.b_leg_status[index] = BLegStatus::Answered;
        }
        // An answered call has no failure left to report, so a response a
        // sibling failed with before the answer is not held for the call's life.
        self.fork_best_failure = None;
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

    /// The best failure among failed B-legs, ranked per RFC 3261 §16.7 step 6
    /// ([`crate::sip::best_response`]); 500 when none has failed.
    pub fn best_error_code(&self) -> u16 {
        crate::sip::best_response::best_status(self.b_leg_status.iter().filter_map(|s| match s {
            BLegStatus::Failed(code) => Some(*code),
            _ => None,
        }))
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

    /// Whether the B-leg at `index` is a branch still waiting for its final
    /// response. The re-INVITE / UPDATE / REFER tracking pseudo-legs share
    /// `b_legs` but are never branches.
    pub fn is_pending_branch(&self, index: usize) -> bool {
        matches!(
            self.b_leg_status.get(index),
            Some(BLegStatus::Trying | BLegStatus::Ringing)
        ) && self
            .b_legs
            .get(index)
            .is_some_and(|leg| !leg.is_tracking_leg())
    }

    /// Whether the B-leg at `index` is a branch that has ended: it has its final
    /// response (answered, failed, an LCR carrier settled), siphon CANCELled it,
    /// or it is no longer on the call. A provisional from such a leg is owed
    /// nothing: no relay, no LCR progress, no PRACK.
    ///
    /// Not quite the negation of [`is_pending_branch`](Self::is_pending_branch):
    /// a re-INVITE / UPDATE / forwarded-request tracking pseudo-leg is neither.
    /// It is no branch, and the reliable provisional a re-INVITE draws is still
    /// PRACKed.
    pub fn is_ended_branch(&self, index: usize) -> bool {
        !self.is_pending_branch(index)
            && !self
                .b_legs
                .get(index)
                .is_some_and(|leg| leg.is_tracking_leg())
    }

    /// Mark every pending branch but `keep` cancelled, and return the ones whose
    /// INVITE is on the wire, for the caller to CANCEL (RFC 3261 §9.1).
    ///
    /// A CANCEL is built from the INVITE it cancels, so a branch whose INVITE is
    /// not stashed yet is flagged `pending_cancel` instead, and the send path
    /// CANCELs it as soon as the stash lands.
    pub fn cancel_pending_branches(&mut self, keep: Option<usize>) -> Vec<Leg> {
        let mut cancelled = Vec::new();
        for index in 0..self.b_legs.len() {
            if Some(index) == keep || !self.is_pending_branch(index) {
                continue;
            }
            if let Some(status) = self.b_leg_status.get_mut(index) {
                *status = BLegStatus::Cancelled;
            }
            if let Some(leg) = self.b_legs.get_mut(index) {
                if leg.b_leg_invite.is_some() {
                    cancelled.push(leg.clone());
                } else {
                    leg.pending_cancel = true;
                }
            }
        }
        cancelled
    }

    /// Record the branch at `index` failing with `response`, and settle the
    /// fork if no branch is left that could still answer.
    ///
    /// A parallel fork fails only once every branch has (RFC 3261 §16.7): one
    /// branch busy while another rings leaves the caller ringing. Meanwhile the
    /// best response is kept, and it is that one, not whichever came last, the
    /// A-leg is sent. A 6xx settles at once and cancels the rest, because it
    /// says no branch will do. `call.dial()` is a fork of one and settles on its
    /// first failure.
    ///
    /// On an answered call this settles and cancels nothing: a failure landing
    /// there is a straggler rather than the call failing, and a leg still
    /// pending on an answered call (a transfer target) is no branch of the fork.
    pub fn record_branch_failure(
        &mut self,
        index: usize,
        status_code: u16,
        response: &SipMessage,
    ) -> BranchSettlement {
        if let Some(status) = self.b_leg_status.get_mut(index) {
            *status = BLegStatus::Failed(status_code);
        }
        if self.state == CallState::Answered {
            return BranchSettlement::default();
        }
        // `map_or(true, …)` not `is_none_or`: MSRV 1.80, and that is 1.82.
        let improves = self.fork_best_failure.as_ref().map_or(true, |best| {
            ResponseRank::of(status_code) > ResponseRank::of(best.status_code)
        });
        if improves {
            if let Some(leg) = self.b_legs.get(index) {
                self.fork_best_failure = Some(BranchFailure {
                    branch: leg.branch.clone(),
                    status_code,
                    response: response.clone(),
                });
            }
        }
        self.settle_fork()
    }

    /// Close the dispatch window [`fork_dispatching`](Self::fork_dispatching)
    /// held open, and settle what happened inside it.
    ///
    /// A branch may have answered before the later ones were sent, and those are
    /// cancelled now instead of ringing beside an answered call. Or every branch
    /// may have failed while the fork was still going out, and this is then the
    /// only place left to report it.
    pub fn finish_fork_dispatch(&mut self) -> BranchSettlement {
        self.fork_dispatching = false;
        if self.state == CallState::Answered {
            return BranchSettlement {
                cancelled: self.cancel_pending_branches(self.winner),
                failure: None,
            };
        }
        self.settle_fork()
    }

    /// Settle the fork when none of its branches can still answer.
    fn settle_fork(&mut self) -> BranchSettlement {
        if self.fork_dispatching {
            return BranchSettlement::default();
        }
        let declined = self
            .fork_best_failure
            .as_ref()
            .is_some_and(|best| (600..700).contains(&best.status_code));
        let cancelled = if declined {
            self.cancel_pending_branches(None)
        } else {
            Vec::new()
        };
        // Only a branch whose INVITE went on the wire (is stashed) can still
        // answer. One whose send failed was never a branch, and must not hold
        // the caller in ringback until the ring timeout.
        let ringing = (0..self.b_legs.len()).any(|index| {
            self.is_pending_branch(index)
                && self
                    .b_legs
                    .get(index)
                    .is_some_and(|leg| leg.b_leg_invite.is_some())
        });
        let failure = if ringing {
            None
        } else {
            self.fork_best_failure.take()
        };
        BranchSettlement { cancelled, failure }
    }

    /// On the ring timeout: the failure this fork already holds, when it beats
    /// the 408 the timeout itself amounts to (RFC 3261 §16.8 counts a branch
    /// that never answered as a 408 in the response context).
    ///
    /// When it does, every branch still ringing is cancelled and the held
    /// failure is handed back for the caller to relay, as it would have been had
    /// those branches failed too. `None` otherwise, and the timeout answers 408.
    pub fn settle_fork_on_timeout(&mut self) -> Option<BranchSettlement> {
        let beats_timeout = self
            .fork_best_failure
            .as_ref()
            .is_some_and(|best| ResponseRank::of(best.status_code) > ResponseRank::of(408));
        if !beats_timeout {
            return None;
        }
        Some(BranchSettlement {
            cancelled: self.cancel_pending_branches(None),
            failure: self.fork_best_failure.take(),
        })
    }

    /// Ready the call to be routed again from `@b2bua.on_failure`, and count
    /// the re-route against the cap.
    ///
    /// What the failed routing left behind goes: the failure its fork held (the
    /// new branches are ranked on their own) and its ring deadline (the new
    /// routing arms its own). Its route sequence goes too when the handler dials
    /// or forks instead (`replaces_route_sequence`), or the new B-leg's failure
    /// would be taken for one of the old carriers'; `call.route()` starts a
    /// sequence of its own. The B-legs that failed stay, settled, so a late
    /// retransmission from one still finds its call.
    pub fn begin_failure_reroute(&mut self, replaces_route_sequence: bool) {
        self.failure_reroutes = self.failure_reroutes.saturating_add(1);
        self.fork_best_failure = None;
        self.answer_deadline = None;
        if replaces_route_sequence {
            self.route_sequence = None;
        }
    }

    /// Take back an answer the call failed on before its caller was connected:
    /// the B-leg at `b_leg_index` answered, `@b2bua.on_answer` raised or ended
    /// the call, and that leg has been released.
    ///
    /// The call is unanswered again, with no winner and no answer time, so
    /// `@b2bua.on_failure` can route it somewhere else and a later answer starts
    /// the duration cap from when it happens. The released leg counts as failed
    /// with `status_code`, the status the call concludes on.
    pub fn rewind_failed_answer(&mut self, b_leg_index: Option<usize>, status_code: u16) {
        if let Some(status) = b_leg_index.and_then(|index| self.b_leg_status.get_mut(index)) {
            *status = BLegStatus::Failed(status_code);
        }
        self.winner = None;
        self.answered_at = None;
        // An ACK held for that answer's offer belonged to the failed answer; the
        // failure path has already ACKed the leg it came from.
        self.delayed_offer_ack = None;
        self.transition_to(CallState::Calling);
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

// ---------------------------------------------------------------------------
// CallActorStore — manages all active calls
// ---------------------------------------------------------------------------

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
/// Keyed by the Via branch of the CANCELled INVITE, which every final response
/// to it carries (RFC 3261 §17.1.3). Not by the Call-ID: under
/// `call.preserve_call_id()` every branch of a fork shares one, and a key per
/// Call-ID kept only the last cancelled branch answerable. Auto-expires after 32
/// seconds (Timer H).
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
/// A fork branch's final failure, held until the fork settles.
#[derive(Debug, Clone)]
pub struct BranchFailure {
    /// Via branch of the leg it came from: the relayed response is rewritten
    /// from that leg's dialog, so the leg has to be found again at settle time.
    pub branch: String,
    /// Its status code.
    pub status_code: u16,
    /// The response itself, relayed to the A-leg if it stays the best.
    pub response: SipMessage,
}

/// What a branch's final failure, or the end of a fork's dispatch, settles.
#[derive(Debug, Default)]
pub struct BranchSettlement {
    /// Branches that are over and must be CANCELled now (RFC 3261 §9.1): the
    /// siblings of a 6xx, or branches sent after another had already answered.
    pub cancelled: Vec<Leg>,
    /// Set once no branch is left that could answer: the best failure across
    /// all of them, which the A-leg is sent. `None` while the call can still be
    /// answered, or when it already has been.
    pub failure: Option<BranchFailure>,
}

/// Outcome of an atomic answer claim ([`CallActorStore::try_win`]).
#[derive(Debug, Clone)]
pub enum WinOutcome {
    /// This 2xx is the first to answer the call: the winner and `Answered`
    /// state were set under the per-call lock, and every branch still ringing
    /// was cancelled under it too. `cancelled` holds those branches, for the
    /// caller to CANCEL (RFC 3261 §9.1).
    FirstWin { cancelled: Vec<Leg> },
    /// The call was already answered: this 2xx is a retransmission of the
    /// winning B-leg's answer (or a losing fork branch's). It is not relayed to
    /// the caller again, and it is ACKed like every 2xx (RFC 3261 §13.2.2.4).
    AlreadyAnswered,
}

/// The ACK owed to a B-leg 2xx that carried the offer, because the INVITE went
/// out without one (see `CallActor::delayed_offer_ack`).
#[derive(Debug, Clone)]
pub struct DelayedOfferAck {
    /// The ACK, built from the 2xx. Carries the answer once `sent`.
    pub ack: crate::sip::message::SipMessage,
    /// The offer the 2xx carried: what a rejecting answer is built against when
    /// the call ends before the caller answers.
    pub offer: Vec<u8>,
    pub transport: crate::transport::Transport,
    /// The ACK's next hop, the first of the 2xx's route set or the leg's address.
    pub destination: std::net::SocketAddr,
    /// The socket the INVITE left from, for a flow-pinned leg.
    pub local_addr: Option<std::net::SocketAddr>,
    /// The B-leg that sent the 2xx.
    pub b_leg_index: usize,
    /// Whether the ACK has gone out. Until it has, copies of the 2xx are absorbed.
    pub sent: bool,
}
