//! Runtime helper that bridges siphon's B2BUA / proxy lifecycle to Ro online
//! charging (Diameter Credit-Control, RFC 8506 / 3GPP TS 32.299). The online
//! analogue of [`super::rf_service`].
//!
//! Three flows:
//!   * **SCUR sessions** — [`RoChargingService::open_session`] reserves credit
//!     (CCR-INITIAL) for one [`RoSessionSpec`] and keeps the credit-control
//!     session in Rust: its own Session-Id, Subscription-Id, Service-Context-Id
//!     and IMS-Information, CC-Request-Number, grant, failure handling and
//!     peer. Any number may be open at once, for one call or for none: a
//!     conference opens one per participant leg, a forwarded call one per
//!     forwarding user, an SCP one per CAMEL dialogue. A session with
//!     [`Metering::Local`] re-authorizes (CCR-UPDATE) on its own clock and
//!     **disconnects the call it is bound to** (via the teardown hook) when the
//!     OCS refuses further credit or its final units are used; one with
//!     [`Metering::External`] is driven by its owner's usage reports
//!     ([`RoChargingService::report_usage`]). An OCS Re-Auth-Request or
//!     Abort-Session-Request for a live session is answered here
//!     ([`RoChargingService::handle_rar`], [`RoChargingService::handle_asr`]).
//!   * **`call.ro_authorize()`** — [`RoChargingService::authorize_call`], one
//!     session bound to a B2BUA call, kept for the scripts written against it.
//!   * **IEC** (SMS/RCS) — [`RoChargingService::charge_event`] does a one-shot
//!     CCR-EVENT (DIRECT_DEBITING) before delivery; no session, no timer.
//!
//! The mechanism (CCR/CCA state machine, timers, enforcement, failover, session
//! store) is entirely Rust-side; policy (which subscriber, rating group, denial
//! response) is the caller's / the script's.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{Mutex, Notify};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::RoConfig;
use crate::diameter::dictionary;
use crate::diameter::peer::DiameterPeer;
use crate::diameter::ro::{
    self, CcRequestType, CcrSendOptions, CreditControlAnswer, CreditControlParams, ImsChargingData,
    NodeFunctionality, ServiceUnit, SmsChargingData, SubscriberId,
    REQUESTED_ACTION_DIRECT_DEBITING,
};
use crate::diameter::DiameterManager;

/// RFC 8506 §9.1 result codes relevant to charging enforcement.
/// DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE — grant the service free of charge,
/// end the CC session, do NOT deny.
const DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE: u32 = 4011;
const DIAMETER_CREDIT_LIMIT_REACHED: u32 = 4012;

/// Credit-Control-Failure-Handling values (RFC 8506 §8.14).
pub const CCFH_TERMINATE: u32 = 0;
pub const CCFH_CONTINUE: u32 = 1;
pub const CCFH_RETRY_AND_TERMINATE: u32 = 2;
/// CC-Session-Failover FAILOVER_SUPPORTED (RFC 8506 §8.4).
const FAILOVER_SUPPORTED: u32 = 1;

/// Bounded metric label for a teardown reason.
///
/// The reason strings themselves are human-readable and reach the teardown hook
/// (and from there scripts and any SIP `Reason` header), so they are left alone;
/// this maps them to stable snake_case series names. An unmapped reason falls to
/// `other` rather than minting a series, so adding a reason string later cannot
/// quietly grow the label set.
fn teardown_reason_label(reason: &str) -> &'static str {
    match reason {
        "credit limit reached" => "credit_limit_reached",
        "credit denied" => "credit_denied",
        "credit exhausted (final unit)" => "final_unit",
        "session lifetime exceeded" => "session_lifetime_exceeded",
        "ocs unreachable" => "ocs_unreachable",
        "aborted by the charging system" => "aborted",
        _ => "other",
    }
}

/// When the chargeable clock starts (`ro.charge_from`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeFrom {
    /// From the 200 OK. TS 32.260 §5: chargeable duration is the answered
    /// duration, so a call that rings and is never answered has none.
    Answer,
    /// From the CCR-INITIAL — the reservation, before any carrier was dialled —
    /// so ring time is billed. The behaviour before `charge_from` existed.
    Invite,
}

impl ChargeFrom {
    /// Parse the config string. Anything unrecognised falls back to `Answer`
    /// with a warning rather than silently billing ring time.
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "invite" => ChargeFrom::Invite,
            "answer" => ChargeFrom::Answer,
            other => {
                warn!(
                    charge_from = %other,
                    "ro: unknown charge_from, using \"answer\""
                );
                ChargeFrom::Answer
            }
        }
    }
}

/// Who measures a session's usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metering {
    /// siphon does: the chargeable clock runs from the answer (or the
    /// reservation, per [`ChargeFrom`]) and the session re-authorizes on its
    /// own when the grant, its threshold or its Validity-Time is reached.
    Local,
    /// The owner does — an SCP whose gsmSSF reports call time in
    /// ApplyChargingReport. Each report is the cumulative figure; siphon sends
    /// the difference to the last one it reported. No re-authorization timer:
    /// the owner reports when its own grant runs out, and is told (with a
    /// [`RoEventKind::Reauthorize`] event) when the OCS asks for one or the
    /// Validity-Time expires.
    External,
}

/// IMS-Information `Cause-Code` (TS 32.299 §7.2.35) for a call siphon cut
/// because the OCS refused further credit.
///
/// The convention is Rf's, shared via [`crate::diameter::rf::sip_status_to_cause_code`]:
/// a successful end is `0`, a failure its SIP status (TS 32.299 V18.0.0 clause
/// 7.2.35, failures >= 1). `402 Payment Required` is what siphon answers when
/// the OCS denies at setup, so an out-of-credit teardown reports the cause a
/// denied setup does: the OCS sees one code for "no credit", whenever it ran out.
const CAUSE_CODE_CREDIT_EXHAUSTED: i32 = 402;

/// `Cause-Code` for a session released by the max-lifetime backstop: no BYE
/// ever arrived, so this is a timeout, reported as `408 Request Timeout`.
const CAUSE_CODE_SESSION_LIFETIME_EXCEEDED: i32 = 408;

/// Never re-authorize faster than this, so a pathological small grant can't
/// hot-loop the OCS.
const MIN_REAUTH_SECS: u32 = 5;
/// Backstop: an abandoned session (no BYE, no session-timer) releases after
/// this long instead of re-authorizing forever.
const MAX_RO_SESSION_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Hook the dispatcher installs so the Rust-side re-auth loop can disconnect a
/// live call from a background task. `(sip_call_id, reason)`.
///
/// The target is the B2BUA call a session is bound to, identified by its SIP
/// Call-ID. A session bound to no call (an SCP's) is never torn down through
/// it: its owner learns of the end from its [`RoEventHook`].
pub type RoTeardownHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// What happened to a session that its owner did not do itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoEventKind {
    /// siphon ended the session: credit refused or used up, the OCS
    /// unreachable, CREDIT_CONTROL_NOT_APPLICABLE mid-session, or the lifetime
    /// backstop. A bound call has been torn down where the reason calls for it.
    Released,
    /// The OCS aborted the session (ASR, RFC 8506 §5.5): answered, CCR-T sent,
    /// a bound call torn down.
    Aborted,
    /// An externally metered session must report now: the OCS sent a RAR, or
    /// the Validity-Time of the grant expired.
    Reauthorize,
}

impl RoEventKind {
    pub fn label(self) -> &'static str {
        match self {
            RoEventKind::Released => "released",
            RoEventKind::Aborted => "aborted",
            RoEventKind::Reauthorize => "reauthorize",
        }
    }
}

/// One event on a session, handed to its [`RoEventHook`].
#[derive(Debug, Clone)]
pub struct RoSessionEvent {
    pub kind: RoEventKind,
    pub reason: String,
    /// The Result-Code that caused it, when an answer did.
    pub result_code: Option<u32>,
    /// Final-Unit-Action of the grant that ran out (RFC 8506 §8.35).
    pub final_unit_action: Option<u32>,
    /// Redirect-Server-Address of that grant, for REDIRECT.
    pub redirect_server_address: Option<String>,
}

/// Per-session observer the owner registers ([`RoSessionSpec::event_hook`]).
pub type RoEventHook = Arc<dyn Fn(&CcCreditSession, &RoSessionEvent) + Send + Sync>;

/// Everything one credit-control session is opened with. Build it with
/// [`RoChargingService::session_spec`] (the `ro:` defaults) and override what
/// differs for this session.
pub struct RoSessionSpec {
    /// The party charged — for a forwarded leg the forwarding user
    /// (TS 32.260 §5.2.2, TS 24.604 §4.5.2.6), for a conference dial-out the
    /// participant who asked for it.
    pub subscriber: SubscriberId,
    /// More Subscription-Ids on every request (the IMSI next to the MSISDN).
    pub additional_subscribers: Vec<SubscriberId>,
    /// VCS-Information on every request (a Proxy Function, TS 32.276).
    pub vcs_data: Option<ro::VcsInformation>,
    /// IMS-Information for every request of the session; `None` sends none
    /// (a session that describes itself otherwise, e.g. VCS-Information).
    pub ims_data: Option<ImsChargingData>,
    pub service_context_id: String,
    pub rating_group: Option<u32>,
    pub service_identifier: Option<u32>,
    /// CC-Time asked for on CCR-I/U; 0 sends an empty Requested-Service-Unit.
    pub requested_seconds: u32,
    pub charge_from: ChargeFrom,
    pub metering: Metering,
    /// SIP Call-ID of the B2BUA call to disconnect when credit runs out.
    /// [`RoChargingService::bind_call`] sets it after the fact too.
    pub teardown_call: Option<String>,
    /// Owner's key to find the session by (a TCAP dialogue id). Unique among
    /// live sessions.
    pub key: Option<String>,
    pub event_hook: Option<RoEventHook>,
}

/// Outcome of a setup-time authorization.
pub enum ChargeDecision {
    /// Credit granted. For SCUR the session handle drives the re-auth loop and
    /// must be stored so BYE can terminate it; for IEC it is `None`.
    Granted(Option<CcCreditSession>),
    /// Credit denied by the OCS — reject the call/message. Carries the OCS
    /// Result-Code (e.g. 4012).
    Denied(u32),
    /// The OCS was unreachable and policy is fail-open — allow, uncharged.
    AllowUncharged,
}

/// The grant a session currently holds, from its last successful CCA.
#[derive(Debug, Clone, Default)]
pub struct RoGrant {
    pub granted_time: Option<u32>,
    pub validity_time: Option<u32>,
    pub time_quota_threshold: Option<u32>,
    pub final_unit_action: Option<u32>,
    /// Tariff-Time-Change, Unix seconds.
    pub tariff_time_change: Option<u64>,
    /// PS-Free-Format-Data from the answer's VCS-Information (TS 32.276).
    pub free_format_data: Option<Vec<u8>>,
}

impl RoGrant {
    fn from_answer(answer: &CreditControlAnswer) -> Self {
        Self {
            granted_time: answer.granted_time,
            validity_time: answer.validity_time,
            time_quota_threshold: answer.time_quota_threshold,
            final_unit_action: answer.final_unit_action,
            tariff_time_change: answer.tariff_time_change,
            free_format_data: answer.free_format_data.clone(),
        }
    }
}

/// Credit-control session (SCUR). Cloneable handle over `Arc` inner state so
/// the re-auth timer, the stores and the owner can share it.
#[derive(Clone)]
pub struct CcCreditSession {
    inner: Arc<CcSessionInner>,
}

struct CcSessionInner {
    session_id: String,
    /// CC-Request-Number: INITIAL=0, UPDATE 1..N, TERMINATION N+1.
    cc_request_number: AtomicU32,
    /// Set once when the session ends (BYE, enforced teardown, or backstop).
    stopped: AtomicU32,
    reauth_handle: Mutex<Option<JoinHandle<()>>>,
    last_result_code: AtomicU32,
    /// SIP Call-ID of the B2BUA call to disconnect on credit exhaustion, if the
    /// session is bound to one.
    teardown_call: StdMutex<Option<String>>,
    /// Internal call id the dispatcher filed this session under by
    /// [`RoChargingService::bind_call`], so ending it removes the entry.
    bound_internal_call: StdMutex<Option<String>>,
    key: Option<String>,
    /// The server this session talks to. Moves on failover (RFC 8506 §5.7).
    peer: StdMutex<Arc<DiameterPeer>>,
    subscriber: SubscriberId,
    additional_subscribers: Vec<SubscriberId>,
    /// VCS-Information for every request of the session; the owner adds the
    /// members it learns later with [`CcCreditSession::update_vcs`]. Only
    /// held to clone out or overlay, never across an await.
    vcs_data: StdMutex<Option<ro::VcsInformation>>,
    service_context_id: String,
    rating_group: Option<u32>,
    service_identifier: Option<u32>,
    requested_seconds: u32,
    metering: Metering,
    /// The `ImsChargingData` built at CCR-INITIAL, carried on the session so
    /// every later request in it can describe the same call.
    ///
    /// A `std::sync::Mutex` rather than a `tokio` one: it is only ever held to
    /// clone the value out, never across an await.
    ims_data: StdMutex<Option<ImsChargingData>>,
    /// Where the chargeable clock starts for this session.
    charge_from: ChargeFrom,
    /// When the reservation was made (CCR-INITIAL); the max-lifetime backstop
    /// measures from here.
    started_at: Instant,
    /// Wall-clock instant of the same moment, for `SIP-Request-Timestamp`.
    requested_at: std::time::SystemTime,
    /// Set once when the call is answered. `None` while it is still ringing.
    answered_at: StdMutex<Option<Instant>>,
    /// The OCS's first-grant CC-Time (seconds).
    initial_grant: u32,
    /// Seconds already reported to the OCS in an *answered* request; the next
    /// Used-Service-Unit carries only what came after (RFC 8506 §5.6).
    reported_secs: AtomicU32,
    /// The grant from the last successful CCA.
    grant: StdMutex<RoGrant>,
    /// Credit-Control-Failure-Handling in force: the configured default until
    /// a CCA carries the AVP (RFC 8506 §5.7).
    failure_handling: AtomicU32,
    /// CC-Session-Failover in force, same precedence.
    failover_supported: AtomicBool,
    /// Wakes the re-auth loop for a RAR (RFC 8506 §5.5).
    wake: Notify,
    reauth_requested: AtomicBool,
    event_hook: Option<RoEventHook>,
}

fn lock<T>(mutex: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl CcCreditSession {
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn last_result_code(&self) -> Option<u32> {
        match self.inner.last_result_code.load(Ordering::Relaxed) {
            0 => None,
            code => Some(code),
        }
    }

    /// The OCS's first-grant CC-Time (seconds).
    pub fn granted_time(&self) -> u32 {
        self.inner.initial_grant
    }

    /// The grant of the last successful answer.
    pub fn grant(&self) -> RoGrant {
        lock(&self.inner.grant).clone()
    }

    /// Lay `update` over the session's VCS-Information for its next requests
    /// (see [`ro::VcsInformation::overlay`]). A session opened without one
    /// starts from `update`.
    pub fn update_vcs(&self, update: ro::VcsInformation) {
        let mut held = lock(&self.inner.vcs_data);
        match held.as_mut() {
            Some(vcs) => vcs.overlay(update),
            None => *held = Some(update),
        }
    }

    fn vcs_snapshot(&self) -> Option<ro::VcsInformation> {
        lock(&self.inner.vcs_data).clone()
    }

    /// The charged party.
    pub fn subscriber(&self) -> &SubscriberId {
        &self.inner.subscriber
    }

    pub fn service_context_id(&self) -> &str {
        &self.inner.service_context_id
    }

    pub fn key(&self) -> Option<&str> {
        self.inner.key.as_deref()
    }

    pub fn metering(&self) -> Metering {
        self.inner.metering
    }

    /// Whether the session is still open.
    pub fn is_open(&self) -> bool {
        self.inner.stopped.load(Ordering::Relaxed) == 0
    }

    /// SIP Call-ID of the call this session releases, if it is bound to one.
    pub fn teardown_call(&self) -> Option<String> {
        lock(&self.inner.teardown_call).clone()
    }

    /// CC-Request-Number the next request will carry.
    pub fn next_request_number(&self) -> u32 {
        self.inner.cc_request_number.load(Ordering::Relaxed)
    }

    /// Credit-Control-Failure-Handling now in force.
    pub fn failure_handling(&self) -> u32 {
        self.inner.failure_handling.load(Ordering::Relaxed)
    }

    fn peer(&self) -> Arc<DiameterPeer> {
        Arc::clone(&lock(&self.inner.peer))
    }

    fn next_cc_request_number(&self) -> u32 {
        self.inner.cc_request_number.fetch_add(1, Ordering::Relaxed)
    }

    /// Take what a successful answer says about the rest of the session: its
    /// grant, and the failure handling the server wants (RFC 8506 §5.7).
    fn absorb(&self, answer: &CreditControlAnswer) {
        self.inner
            .last_result_code
            .store(answer.result_code, Ordering::Relaxed);
        if let Some(ccfh) = answer.credit_control_failure_handling {
            self.inner.failure_handling.store(ccfh, Ordering::Relaxed);
        }
        if let Some(failover) = answer.cc_session_failover {
            self.inner
                .failover_supported
                .store(failover == FAILOVER_SUPPORTED, Ordering::Relaxed);
        }
        if answer.is_success() {
            *lock(&self.inner.grant) = RoGrant::from_answer(answer);
        }
    }

    /// Snapshot the session's `ImsChargingData` for one outgoing request,
    /// stamped with `cause_code` and this record's timestamp.
    ///
    /// `cause_code` is `None` on a CCR-UPDATE (the session has not ended, so
    /// there is no cause to report) and `Some` on a CCR-TERMINATION.
    fn charging_data_for(
        &self,
        sip_method: &str,
        cause_code: Option<i32>,
    ) -> Option<ImsChargingData> {
        let mut data = lock(&self.inner.ims_data).clone()?;
        data.sip_method = Some(sip_method.to_string());
        data.cause_code = cause_code;
        // Time-Stamps describes *this* record's trigger, not the INVITE the
        // INITIAL already reported (TS 32.299 §7.2.183).
        let now = std::time::SystemTime::now();
        data.request_timestamp = Some(now);
        data.response_timestamp = Some(now);
        Some(data)
    }

    /// Seconds of *chargeable* time elapsed so far (local metering).
    ///
    /// Under `charge_from: answer` this is zero until the call is answered and
    /// counts from the 200 OK thereafter. Under `charge_from: invite` it is the
    /// whole session age.
    fn chargeable_secs(&self) -> u32 {
        match self.inner.charge_from {
            ChargeFrom::Invite => self.inner.started_at.elapsed().as_secs() as u32,
            ChargeFrom::Answer => match self.answered_at() {
                Some(answered_at) => answered_at.elapsed().as_secs() as u32,
                None => 0,
            },
        }
    }

    fn answered_at(&self) -> Option<Instant> {
        *lock(&self.inner.answered_at)
    }

    /// Usage not yet reported to the OCS (local metering), and therefore what
    /// the next Used-Service-Unit must carry (RFC 8506 §5.6).
    fn unreported_secs(&self) -> u32 {
        self.chargeable_secs()
            .saturating_sub(self.inner.reported_secs.load(Ordering::Relaxed))
    }

    /// The part of a cumulative usage figure not yet reported (external
    /// metering). A figure below what was already reported reports nothing.
    fn unreported_of(&self, used_total: u32) -> u32 {
        used_total.saturating_sub(self.inner.reported_secs.load(Ordering::Relaxed))
    }

    /// Mark the call answered, starting the chargeable clock under
    /// `charge_from: answer`. Idempotent — a retransmitted 200 OK must not
    /// restart it.
    fn mark_answered(&self) -> bool {
        let mut guard = lock(&self.inner.answered_at);
        if guard.is_some() {
            return false;
        }
        *guard = Some(Instant::now());
        true
    }

    /// The `ImsChargingData` for the answer-time CCR-UPDATE, carrying the real
    /// `Time-Stamps` pair: the INVITE that triggered the reservation, and the
    /// answer now.
    fn answer_charging_data(&self) -> Option<ImsChargingData> {
        let mut data = lock(&self.inner.ims_data).clone()?;
        data.sip_method = Some("INVITE".to_string());
        data.cause_code = None;
        data.request_timestamp = Some(self.inner.requested_at);
        data.response_timestamp = Some(std::time::SystemTime::now());
        Some(data)
    }

    /// Record the carrier that actually carried the call, as
    /// `Outgoing-Trunk-Group-Id` (TS 32.299 §7.2.71).
    pub fn set_outgoing_trunk_group(&self, carrier_id: &str) {
        if let Some(data) = lock(&self.inner.ims_data).as_mut() {
            data.outgoing_trunk_group_id = Some(carrier_id.to_string());
        }
    }

    fn requested_units(&self) -> Option<ServiceUnit> {
        (self.inner.requested_seconds > 0).then(|| ServiceUnit {
            time_seconds: Some(self.inner.requested_seconds),
            ..Default::default()
        })
    }

    fn params<'a>(
        &'a self,
        request_type: CcRequestType,
        request_number: u32,
        ims_data: Option<&'a ImsChargingData>,
        vcs_data: Option<&'a ro::VcsInformation>,
        requested: Option<&'a ServiceUnit>,
        used: Option<&'a ServiceUnit>,
    ) -> CreditControlParams<'a> {
        CreditControlParams {
            request_type,
            request_number,
            subscriber: &self.inner.subscriber,
            service_context_id: &self.inner.service_context_id,
            session_id: Some(&self.inner.session_id),
            ims_data,
            sms_data: None,
            requested_units: requested,
            used_units: used,
            rating_group: self.inner.rating_group,
            service_identifier: self.inner.service_identifier,
            requested_action: None,
            multiple_services_indicator: false,
            additional_subscribers: &self.inner.additional_subscribers,
            vcs_data,
        }
    }

    fn emit(&self, event: RoSessionEvent) {
        if let Some(hook) = self.inner.event_hook.as_ref() {
            hook(self, &event);
        }
    }
}

/// Re-authorization deadline from a CCA (RFC 8506 §5.1.2, TS 32.299 §6.3.5):
/// the earlier of the granted CC-Time less its Time-Quota-Threshold, and the
/// Validity-Time; the configured fallback when the answer grants neither.
fn reauth_after(answer: &CreditControlAnswer, fallback: u32) -> u32 {
    let quota = answer
        .granted_time
        .filter(|granted| *granted > 0)
        .map(|granted| granted.saturating_sub(answer.time_quota_threshold.unwrap_or(0)));
    let validity = answer.validity_time.filter(|validity| *validity > 0);
    let deadline = match (quota, validity) {
        (Some(quota), Some(validity)) => quota.min(validity),
        (Some(quota), None) => quota,
        (None, Some(validity)) => validity,
        (None, None) => fallback,
    };
    deadline.max(MIN_REAUTH_SECS)
}

/// Online-charging service. Holds the OCS peer resolution, the live sessions,
/// and the teardown hook.
pub struct RoChargingService {
    manager: Arc<DiameterManager>,
    config: RoConfig,
    node_functionality: Option<NodeFunctionality>,
    /// Resolved `ro.charge_from`, parsed once at construction.
    charge_from: ChargeFrom,
    active_sessions: Arc<AtomicUsize>,
    teardown_hook: StdMutex<Option<RoTeardownHook>>,
    /// Every open session by Session-Id: what a RAR or ASR is matched against.
    live: DashMap<String, CcCreditSession>,
    /// Open sessions by their owner's key.
    keys: DashMap<String, CcCreditSession>,
    /// Sessions filed under a B2BUA call by [`Self::bind_call`], by internal
    /// call id: they end with the call.
    bound: DashMap<String, Vec<CcCreditSession>>,
}

impl RoChargingService {
    pub fn new(manager: Arc<DiameterManager>, config: RoConfig) -> Arc<Self> {
        let node_functionality = NodeFunctionality::from_str_ci(&config.node_functionality);
        if node_functionality.is_none() {
            warn!(
                node_functionality = %config.node_functionality,
                "ro: unrecognized node_functionality, will be omitted from CCRs"
            );
        }
        let charge_from = ChargeFrom::from_config(&config.charge_from);
        Arc::new(Self {
            manager,
            config,
            node_functionality,
            charge_from,
            active_sessions: Arc::new(AtomicUsize::new(0)),
            teardown_hook: StdMutex::new(None),
            live: DashMap::new(),
            keys: DashMap::new(),
            bound: DashMap::new(),
        })
    }

    pub fn config(&self) -> &RoConfig {
        &self.config
    }

    pub fn node_functionality(&self) -> Option<NodeFunctionality> {
        self.node_functionality
    }

    /// Install the call-teardown hook (dispatcher wiring).
    pub fn set_teardown_hook(&self, hook: RoTeardownHook) {
        *lock(&self.teardown_hook) = Some(hook);
    }

    /// Number of live credit-control sessions — the per-module leak gate.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }

    /// An open session by Session-Id.
    pub fn session(&self, session_id: &str) -> Option<CcCreditSession> {
        self.live.get(session_id).map(|entry| entry.clone())
    }

    /// An open session by its owner's key.
    pub fn session_by_key(&self, key: &str) -> Option<CcCreditSession> {
        self.keys.get(key).map(|entry| entry.clone())
    }

    /// The `ro:` defaults for a session charged to `subscriber`.
    pub fn session_spec(
        &self,
        subscriber: SubscriberId,
        ims_data: Option<ImsChargingData>,
    ) -> RoSessionSpec {
        RoSessionSpec {
            subscriber,
            additional_subscribers: Vec::new(),
            vcs_data: None,
            ims_data,
            service_context_id: self.config.service_context_id.clone(),
            rating_group: self.config.rating_group,
            service_identifier: self.config.service_identifier,
            requested_seconds: self.config.requested_seconds,
            charge_from: self.charge_from,
            metering: Metering::Local,
            teardown_call: None,
            key: None,
            event_hook: None,
        }
    }

    fn track_session_started(&self, session: &CcCreditSession) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = crate::metrics::metrics() {
            metrics.ro_sessions.inc();
        }
        self.live
            .insert(session.inner.session_id.clone(), session.clone());
        if let Some(key) = session.inner.key.as_ref() {
            self.keys.insert(key.clone(), session.clone());
        }
    }

    /// Flip `session` to stopped exactly once, release its slot from the
    /// count/gauge and drop it from every index. Returns `true` only for the
    /// caller that won the race.
    fn claim_stop(&self, session: &CcCreditSession) -> bool {
        let won = session
            .inner
            .stopped
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        if won {
            self.active_sessions.fetch_sub(1, Ordering::Relaxed);
            if let Some(metrics) = crate::metrics::metrics() {
                metrics.ro_sessions.dec();
            }
            self.live.remove(&session.inner.session_id);
            if let Some(key) = session.inner.key.as_ref() {
                self.keys
                    .remove_if(key, |_, held| Arc::ptr_eq(&held.inner, &session.inner));
            }
            let bound = lock(&session.inner.bound_internal_call).take();
            if let Some(internal_call_id) = bound {
                let empty = match self.bound.get_mut(&internal_call_id) {
                    Some(mut sessions) => {
                        sessions.retain(|held| !Arc::ptr_eq(&held.inner, &session.inner));
                        sessions.is_empty()
                    }
                    None => false,
                };
                if empty {
                    self.bound
                        .remove_if(&internal_call_id, |_, sessions| sessions.is_empty());
                }
            }
        }
        won
    }

    fn fire_teardown(&self, session: &CcCreditSession, reason: &str) {
        let Some(sip_call_id) = session.teardown_call() else {
            // Bound to no call: the owner is told through its event hook.
            return;
        };
        let hook = lock(&self.teardown_hook).clone();
        match hook {
            Some(hook) => {
                crate::metrics::record_ro_credit_teardown(teardown_reason_label(reason));
                hook(&sip_call_id, reason)
            }
            None => {
                // Distinct label: credit ran out, nothing was wired to enforce
                // it, and the call is still up and unpaid.
                crate::metrics::record_ro_credit_teardown("no_teardown_hook");
                warn!(
                    call_id = %sip_call_id,
                    "ro: credit exhausted but no teardown hook installed; call not disconnected"
                )
            }
        }
    }

    // ── Binding to B2BUA calls ──────────────────────────────────────────

    /// Bind `session` to a B2BUA call: credit exhaustion disconnects that call
    /// (by `sip_call_id`), and the call's end terminates the session (the
    /// dispatcher calls [`Self::end_bound`] with `internal_call_id`). Several
    /// sessions may be bound to one call. Returns `false` for a session that
    /// has already ended.
    pub fn bind_call(
        &self,
        session: &CcCreditSession,
        internal_call_id: &str,
        sip_call_id: &str,
    ) -> bool {
        if !session.is_open() {
            return false;
        }
        *lock(&session.inner.teardown_call) = Some(sip_call_id.to_string());
        let previous =
            lock(&session.inner.bound_internal_call).replace(internal_call_id.to_string());
        if previous.as_deref() == Some(internal_call_id) {
            return true;
        }
        if let Some(previous) = previous {
            if let Some(mut sessions) = self.bound.get_mut(&previous) {
                sessions.retain(|held| !Arc::ptr_eq(&held.inner, &session.inner));
            }
        }
        self.bound
            .entry(internal_call_id.to_string())
            .or_default()
            .push(session.clone());
        // Lost a race with the session's end: undo, so nothing is filed for a
        // session that will never be removed by its stop.
        if !session.is_open() {
            if let Some(mut sessions) = self.bound.get_mut(internal_call_id) {
                sessions.retain(|held| !Arc::ptr_eq(&held.inner, &session.inner));
            }
            return false;
        }
        true
    }

    /// Sessions bound to a call (by internal call id).
    pub fn bound_sessions(&self, internal_call_id: &str) -> Vec<CcCreditSession> {
        self.bound
            .get(internal_call_id)
            .map(|sessions| sessions.clone())
            .unwrap_or_default()
    }

    /// Internal call ids that have sessions bound to them.
    pub fn bound_call_ids(&self) -> Vec<String> {
        self.bound.iter().map(|entry| entry.key().clone()).collect()
    }

    /// The call ended: terminate every session bound to it.
    pub async fn end_bound(&self, internal_call_id: &str, cause_code: Option<i32>) {
        let Some((_, sessions)) = self.bound.remove(internal_call_id) else {
            return;
        };
        for session in sessions {
            self.terminate_call(&session, cause_code).await;
        }
    }

    /// The call was answered: start the clock of every session bound to it.
    pub async fn answer_bound(&self, internal_call_id: &str) {
        for session in self.bound_sessions(internal_call_id) {
            self.report_answer(&session).await;
        }
    }

    // ── Peers and failover ──────────────────────────────────────────────

    fn pick_peer(&self) -> Option<Arc<DiameterPeer>> {
        if let Some(name) = self.config.peer.as_deref() {
            if let Some(client) = self.manager.client(name) {
                return Some(client.peer().clone());
            }
            warn!(peer = %name, "ro: configured OCS peer not connected, falling back to the application route");
        }
        self.manager
            .route_client(&crate::config::DiameterApplication::Ro, None)
            .map(|c| c.peer().clone())
    }

    /// Another connected peer on the `ro` route than `current`.
    fn alternate_peer(&self, current: &Arc<DiameterPeer>) -> Option<Arc<DiameterPeer>> {
        self.manager
            .route_clients(&crate::config::DiameterApplication::Ro)
            .into_iter()
            .map(|client| client.peer().clone())
            .find(|peer| !Arc::ptr_eq(peer, current))
    }

    fn send_options(&self, end_to_end: u32, retransmit: bool) -> CcrSendOptions {
        CcrSendOptions {
            end_to_end: Some(end_to_end),
            retransmit,
            timeout: (self.config.tx_timeout_ms > 0)
                .then(|| Duration::from_millis(self.config.tx_timeout_ms as u64)),
        }
    }

    /// The configured default Credit-Control-Failure-Handling.
    fn default_failure_handling(&self) -> u32 {
        let value = self.config.on_ocs_failure.trim().to_ascii_lowercase();
        match value.as_str() {
            "continue" => CCFH_CONTINUE,
            "retry_and_terminate" | "retry-and-terminate" => CCFH_RETRY_AND_TERMINATE,
            _ => CCFH_TERMINATE,
        }
    }

    fn fail_closed(&self) -> bool {
        self.default_failure_handling() != CCFH_CONTINUE
    }

    /// Send one request, failing over once to another `ro` peer when the
    /// server does not answer and both the failure handling and
    /// CC-Session-Failover allow it (RFC 8506 §5.7). The re-sent request keeps
    /// its End-to-End Identifier and CC-Request-Number and carries the T flag.
    /// Returns the answer and the peer that gave it.
    async fn exchange(
        &self,
        peer: &Arc<DiameterPeer>,
        params: &CreditControlParams<'_>,
        failure_handling: u32,
        failover_supported: bool,
    ) -> Result<(CreditControlAnswer, Arc<DiameterPeer>), String> {
        let end_to_end = peer.next_e2e();
        let first = ro::send_ccr_with(peer, params, &self.send_options(end_to_end, false)).await;
        let error = match first {
            Ok(answer) => return Ok((answer, Arc::clone(peer))),
            Err(error) => error,
        };
        if failure_handling == CCFH_TERMINATE || !failover_supported {
            return Err(error);
        }
        let Some(alternate) = self.alternate_peer(peer) else {
            return Err(error);
        };
        warn!(
            session = params.session_id.unwrap_or("-"),
            error = %error,
            from = %peer.config().host,
            to = %alternate.config().host,
            "ro: no answer from the charging server, failing over"
        );
        match ro::send_ccr_with(&alternate, params, &self.send_options(end_to_end, true)).await {
            Ok(answer) => Ok((answer, alternate)),
            Err(retry_error) => Err(format!("{error}; failover: {retry_error}")),
        }
    }

    /// [`Self::exchange`] for a request of an open session: its peer, its
    /// failure handling, and its peer moved to the one that answered.
    async fn exchange_in(
        &self,
        session: &CcCreditSession,
        params: &CreditControlParams<'_>,
    ) -> Result<CreditControlAnswer, String> {
        let peer = session.peer();
        let (answer, answered_by) = self
            .exchange(
                &peer,
                params,
                session.failure_handling(),
                session.inner.failover_supported.load(Ordering::Relaxed),
            )
            .await?;
        if !Arc::ptr_eq(&answered_by, &peer) {
            *lock(&session.inner.peer) = answered_by;
        }
        session.absorb(&answer);
        Ok(answer)
    }

    // ── Opening sessions ────────────────────────────────────────────────

    /// SCUR: reserve credit at call setup (CCR-INITIAL) for one call, bound to
    /// it by SIP Call-ID. The `call.ro_authorize()` path: a session with the
    /// `ro:` defaults, metered locally.
    pub async fn authorize_call(
        self: &Arc<Self>,
        subscriber: SubscriberId,
        ims_data: ImsChargingData,
        sip_call_id: String,
    ) -> ChargeDecision {
        let mut spec = self.session_spec(subscriber, Some(ims_data));
        spec.teardown_call = Some(sip_call_id);
        self.open_session(spec).await
    }

    /// Open a credit-control session (CCR-INITIAL). On a grant the session is
    /// registered (by Session-Id, and by key when it has one), its timer armed,
    /// and the handle returned for the owner to keep.
    pub async fn open_session(self: &Arc<Self>, spec: RoSessionSpec) -> ChargeDecision {
        if !self.config.enabled {
            return ChargeDecision::AllowUncharged;
        }
        let RoSessionSpec {
            subscriber,
            additional_subscribers,
            vcs_data,
            mut ims_data,
            service_context_id,
            rating_group,
            service_identifier,
            requested_seconds,
            charge_from,
            metering,
            teardown_call,
            key,
            event_hook,
        } = spec;
        if let Some(key) = key.as_deref() {
            if self.keys.contains_key(key) {
                warn!(key = %key, "ro: a session is already open under this key");
                return ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_COMPLY);
            }
        }
        let Some(peer) = self.pick_peer() else {
            return if self.fail_closed() {
                crate::metrics::record_ro_denial(dictionary::DIAMETER_UNABLE_TO_DELIVER);
                ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
            } else {
                ChargeDecision::AllowUncharged
            };
        };
        if let Some(data) = ims_data.as_mut() {
            if data.node_functionality.is_none() {
                data.node_functionality = self.node_functionality;
            }
            // The session keeps this copy for its re-authorizations and its
            // termination, so the setting holds for every CCR of the call.
            if !self.config.access_network_information {
                data.access_network_information.clear();
            }
        }
        // Minted here rather than by the sender, so a CCR-INITIAL re-sent to
        // another server on failover is the same request (RFC 8506 §5.7).
        let new_session_id = peer.new_session_id();

        let requested = (requested_seconds > 0).then(|| ServiceUnit {
            time_seconds: Some(requested_seconds),
            ..Default::default()
        });
        let params = CreditControlParams {
            request_type: CcRequestType::Initial,
            request_number: 0,
            subscriber: &subscriber,
            service_context_id: &service_context_id,
            session_id: Some(&new_session_id),
            ims_data: ims_data.as_ref(),
            sms_data: None,
            requested_units: requested.as_ref(),
            used_units: None,
            rating_group,
            service_identifier,
            requested_action: None,
            multiple_services_indicator: true,
            additional_subscribers: &additional_subscribers,
            vcs_data: vcs_data.as_ref(),
        };
        let failure_handling = self.default_failure_handling();
        let (answer, peer) = match self
            .exchange(
                &peer,
                &params,
                failure_handling,
                self.config.session_failover,
            )
            .await
        {
            Ok(exchanged) => exchanged,
            Err(error) => {
                warn!(error = %error, "ro: CCR-INITIAL failed");
                return if failure_handling != CCFH_CONTINUE {
                    crate::metrics::record_ro_denial(dictionary::DIAMETER_UNABLE_TO_DELIVER);
                    ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
                } else {
                    ChargeDecision::AllowUncharged
                };
            }
        };

        if answer.result_code == DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE {
            // Free of charge — no session, call proceeds unmonitored.
            info!(
                "ro: CCR-INITIAL returned CREDIT_CONTROL_NOT_APPLICABLE, call proceeds uncharged"
            );
            return ChargeDecision::AllowUncharged;
        }
        if !answer.is_success() {
            crate::metrics::record_ro_denial(answer.result_code);
            info!(result_code = answer.result_code, "ro: CCR-INITIAL denied");
            return ChargeDecision::Denied(answer.result_code);
        }

        let session_id = match answer.session_id.clone() {
            Some(id) => id,
            None => {
                warn!("ro: CCA-INITIAL carried no Session-Id, cannot track session");
                return ChargeDecision::AllowUncharged;
            }
        };

        let first_wait = reauth_after(&answer, self.config.reauth_interval_secs);
        let session = CcCreditSession {
            inner: Arc::new(CcSessionInner {
                session_id,
                cc_request_number: AtomicU32::new(1),
                stopped: AtomicU32::new(0),
                reauth_handle: Mutex::new(None),
                last_result_code: AtomicU32::new(0),
                teardown_call: StdMutex::new(teardown_call),
                bound_internal_call: StdMutex::new(None),
                key,
                peer: StdMutex::new(peer),
                subscriber,
                additional_subscribers,
                vcs_data: StdMutex::new(vcs_data),
                service_context_id,
                rating_group,
                service_identifier,
                requested_seconds,
                metering,
                ims_data: StdMutex::new(ims_data),
                charge_from,
                started_at: Instant::now(),
                requested_at: std::time::SystemTime::now(),
                answered_at: StdMutex::new(None),
                initial_grant: answer
                    .granted_time
                    .filter(|granted| *granted > 0)
                    .unwrap_or(first_wait),
                reported_secs: AtomicU32::new(0),
                grant: StdMutex::new(RoGrant::default()),
                failure_handling: AtomicU32::new(failure_handling),
                failover_supported: AtomicBool::new(self.config.session_failover),
                wake: Notify::new(),
                reauth_requested: AtomicBool::new(false),
                event_hook,
            }),
        };
        session.absorb(&answer);
        self.track_session_started(&session);
        // If the OCS already flagged this (initial) grant final — the
        // low-balance case where the whole balance fits in one grant — consume
        // it, then cut, without ever sending a CCR-UPDATE.
        let initial_final = answer.final_unit_action.is_some();
        self.spawn_session_timer(&session, first_wait, initial_final)
            .await;

        info!(
            session_id = %session.inner.session_id,
            subscriber = %session.inner.subscriber.data,
            first_wait,
            "ro: CCR-INITIAL granted, session open"
        );
        ChargeDecision::Granted(Some(session))
    }

    /// IEC: one-shot event charging for SMS/RCS (CCR-EVENT, DIRECT_DEBITING).
    /// No session is created.
    pub async fn charge_event(
        &self,
        subscriber: SubscriberId,
        service_context_id: &str,
        ims_data: Option<&ImsChargingData>,
        sms_data: Option<&SmsChargingData>,
    ) -> ChargeDecision {
        if !self.config.enabled {
            return ChargeDecision::AllowUncharged;
        }
        let Some(peer) = self.pick_peer() else {
            return if self.fail_closed() {
                crate::metrics::record_ro_denial(dictionary::DIAMETER_UNABLE_TO_DELIVER);
                ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
            } else {
                ChargeDecision::AllowUncharged
            };
        };
        let params = CreditControlParams {
            request_type: CcRequestType::Event,
            request_number: 0,
            subscriber: &subscriber,
            service_context_id,
            session_id: None,
            ims_data,
            sms_data,
            requested_units: None,
            used_units: None,
            rating_group: None,
            service_identifier: None,
            requested_action: Some(REQUESTED_ACTION_DIRECT_DEBITING),
            multiple_services_indicator: false,
            additional_subscribers: &[],
            vcs_data: None,
        };
        match ro::send_ccr(&peer, &params).await {
            Ok(answer) if answer.is_success() => {
                debug!("ro: CCR-EVENT (IEC) debited");
                ChargeDecision::Granted(None)
            }
            Ok(answer) => {
                crate::metrics::record_ro_denial(answer.result_code);
                info!(
                    result_code = answer.result_code,
                    "ro: CCR-EVENT (IEC) denied"
                );
                ChargeDecision::Denied(answer.result_code)
            }
            Err(error) => {
                warn!(error = %error, "ro: CCR-EVENT (IEC) failed");
                if self.fail_closed() {
                    crate::metrics::record_ro_denial(dictionary::DIAMETER_UNABLE_TO_DELIVER);
                    ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
                } else {
                    ChargeDecision::AllowUncharged
                }
            }
        }
    }

    // ── Session lifecycle ───────────────────────────────────────────────

    /// Report that the call was answered: start the chargeable clock (under
    /// `charge_from: answer`) and tell the OCS, with a CCR-UPDATE carrying
    /// `Time-Stamps` (TS 32.299 §7.2.97).
    ///
    /// Idempotent: a retransmitted 200 OK does not restart the clock or send a
    /// second request. A no-op on a session already stopped, and on an
    /// externally metered one (its owner's clock is the one that counts).
    pub async fn report_answer(&self, session: &CcCreditSession) {
        if !session.is_open() || session.inner.metering == Metering::External {
            return;
        }
        if !session.mark_answered() {
            return;
        }

        // Whatever is chargeable at this instant — zero under
        // `charge_from: answer`, the ring time under `charge_from: invite`.
        let unreported = session.unreported_secs();
        let used = ServiceUnit {
            time_seconds: Some(unreported),
            ..Default::default()
        };
        let requested = session.requested_units();
        let ims_data = session.answer_charging_data();
        let record_number = session.next_cc_request_number();
        let vcs_data = session.vcs_snapshot();
        let params = session.params(
            CcRequestType::Update,
            record_number,
            ims_data.as_ref(),
            vcs_data.as_ref(),
            requested.as_ref(),
            Some(&used),
        );

        match self.exchange_in(session, &params).await {
            Ok(answer) => {
                if unreported > 0 {
                    session
                        .inner
                        .reported_secs
                        .fetch_add(unreported, Ordering::Relaxed);
                }
                info!(
                    session_id = %session.inner.session_id,
                    result_code = answer.result_code,
                    "ro: CCR-UPDATE sent at answer, charging clock started"
                );
            }
            // The clock has already started locally, so a failed report costs
            // one record, not the call's chargeable duration.
            Err(error) => warn!(
                session_id = %session.inner.session_id,
                error = %error,
                "ro: CCR-UPDATE at answer failed"
            ),
        }
    }

    /// Externally metered session: report the cumulative usage `used_total`
    /// (seconds since the call was answered, as the owner's network element
    /// counted it) and ask for more (CCR-UPDATE). siphon sends the difference
    /// to the last answered report as Used-Service-Unit.
    ///
    /// A refusal ends the session (CCR-TERMINATION reporting nothing more) and
    /// is returned for the owner to act on — it is the owner's call to release.
    /// A request that gets no answer from any server leaves the session open
    /// under CONTINUE and ends it under the other failure handlings; either way
    /// the error is returned. `Err` too for a session already ended.
    pub async fn report_usage(
        self: &Arc<Self>,
        session: &CcCreditSession,
        used_total: u32,
    ) -> Result<CreditControlAnswer, String> {
        if !session.is_open() {
            return Err("the credit-control session has ended".to_string());
        }
        let unreported = session.unreported_of(used_total);
        let used = ServiceUnit {
            time_seconds: Some(unreported),
            ..Default::default()
        };
        let requested = session.requested_units();
        let ims_data = session.charging_data_for("INVITE", None);
        let record_number = session.next_cc_request_number();
        let vcs_data = session.vcs_snapshot();
        let params = session.params(
            CcRequestType::Update,
            record_number,
            ims_data.as_ref(),
            vcs_data.as_ref(),
            requested.as_ref(),
            Some(&used),
        );
        match self.exchange_in(session, &params).await {
            Ok(answer) => {
                session
                    .inner
                    .reported_secs
                    .fetch_add(unreported, Ordering::Relaxed);
                if answer.is_success() {
                    // A new grant: the Validity-Time clock restarts from it.
                    self.restart_session_timer(session).await;
                } else if self.claim_stop(session) {
                    info!(session_id = %session.inner.session_id,
                        result_code = answer.result_code,
                        "ro: CCR-UPDATE refused, session ends");
                    self.abort_timer(session).await;
                    if answer.result_code != DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE {
                        self.send_terminate(session, Some(CAUSE_CODE_CREDIT_EXHAUSTED), 0)
                            .await;
                    }
                }
                Ok(answer)
            }
            Err(error) => {
                if session.failure_handling() != CCFH_CONTINUE && self.claim_stop(session) {
                    warn!(session_id = %session.inner.session_id, error = %error,
                        "ro: CCR-UPDATE unanswered, session ends (failure handling)");
                    self.abort_timer(session).await;
                }
                Err(error)
            }
        }
    }

    /// Send CCR-TERMINATION for a session. Idempotent — a session already
    /// stopped is a no-op. `cause_code` is the IMS-Information `Cause-Code`
    /// (TS 32.299 §7.2.35), in the negative-SIP convention Rf's ACR-STOP uses;
    /// `None` omits the AVP. Local metering reports the unreported chargeable
    /// time.
    pub async fn terminate_call(&self, session: &CcCreditSession, cause_code: Option<i32>) {
        self.terminate_with(session, None, cause_code, None).await;
    }

    /// Externally metered session: end it reporting the cumulative usage
    /// `used_total` (CCR-TERMINATION with the difference to the last report).
    pub async fn terminate_with_usage(
        &self,
        session: &CcCreditSession,
        used_total: u32,
        cause_code: Option<i32>,
    ) {
        self.terminate_with(session, Some(used_total), cause_code, None)
            .await;
    }

    /// End a session with what its owner learnt at the release: `vcs` is laid
    /// over its VCS-Information for the CCR-TERMINATION alone (ISUP-Cause and
    /// Stop-Time are TERMINATION-only, TS 32.276 table 6.3.1.4.1), after the
    /// session is claimed so no re-authorization still in its timer can carry
    /// them. `used_total` is the final cumulative usage (external metering),
    /// of which the part not yet reported goes out; `None` reports what local
    /// metering counted, nothing for an external session. Idempotent.
    pub async fn terminate_with(
        &self,
        session: &CcCreditSession,
        used_total: Option<u32>,
        cause_code: Option<i32>,
        vcs: Option<ro::VcsInformation>,
    ) {
        if !self.claim_stop(session) {
            return;
        }
        self.abort_timer(session).await;
        if let Some(vcs) = vcs {
            session.update_vcs(vcs);
        }
        let unreported = match (used_total, session.inner.metering) {
            (Some(used_total), _) => session.unreported_of(used_total),
            (None, Metering::Local) => session.unreported_secs(),
            (None, Metering::External) => 0,
        };
        self.send_terminate(session, cause_code, unreported).await;
    }

    async fn abort_timer(&self, session: &CcCreditSession) {
        if let Some(handle) = session.inner.reauth_handle.lock().await.take() {
            handle.abort();
        }
    }

    /// Build + send a CCR-TERMINATION reporting `unreported` seconds. Does not
    /// touch the stopped flag (callers use `claim_stop` first).
    async fn send_terminate(
        &self,
        session: &CcCreditSession,
        cause_code: Option<i32>,
        unreported: u32,
    ) {
        let used = ServiceUnit {
            time_seconds: Some(unreported),
            ..Default::default()
        };
        let record_number = session.next_cc_request_number();
        // Describe the call on the final record too, not just on the INITIAL.
        let ims_data = session.charging_data_for("BYE", cause_code);
        let vcs_data = session.vcs_snapshot();
        let params = session.params(
            CcRequestType::Termination,
            record_number,
            ims_data.as_ref(),
            vcs_data.as_ref(),
            None,
            Some(&used),
        );
        match self.exchange_in(session, &params).await {
            Ok(answer) => {
                info!(
                    session_id = %session.inner.session_id,
                    result_code = answer.result_code,
                    "ro: CCR-TERMINATION sent"
                );
            }
            Err(error) => warn!(
                session_id = %session.inner.session_id,
                error = %error,
                "ro: CCR-TERMINATION failed"
            ),
        }
    }

    // ── Requests from the OCS ───────────────────────────────────────────

    /// A Re-Auth-Request (RFC 8506 §5.5) for `session_id`. `Some(2001)` when
    /// the session is one of ours — a locally metered session sends its
    /// CCR-UPDATE now, an externally metered one tells its owner to report —
    /// and `None` when it is not (the caller passes the request on).
    pub fn handle_rar(&self, session_id: &str) -> Option<u32> {
        let session = self.session(session_id)?;
        info!(session_id = %session_id, "ro: Re-Auth-Request from the charging system");
        match session.inner.metering {
            Metering::Local => {
                session
                    .inner
                    .reauth_requested
                    .store(true, Ordering::Release);
                session.inner.wake.notify_one();
            }
            Metering::External => session.emit(RoSessionEvent {
                kind: RoEventKind::Reauthorize,
                reason: "re-auth requested by the charging system".to_string(),
                result_code: None,
                final_unit_action: None,
                redirect_server_address: None,
            }),
        }
        Some(dictionary::DIAMETER_SUCCESS)
    }

    /// An Abort-Session-Request (RFC 8506 §5.5, RFC 6733 §8.5) for
    /// `session_id`. `Some(2001)` when the session is one of ours: it is
    /// ended — bound call torn down, owner told, CCR-TERMINATION sent in the
    /// background — and `None` when it is not.
    pub fn handle_asr(self: &Arc<Self>, session_id: &str) -> Option<u32> {
        let session = self.session(session_id)?;
        if !self.claim_stop(&session) {
            return Some(dictionary::DIAMETER_SUCCESS);
        }
        info!(session_id = %session_id, "ro: Abort-Session-Request from the charging system, ending the session");
        let reason = "aborted by the charging system";
        self.fire_teardown(&session, reason);
        session.emit(RoSessionEvent {
            kind: RoEventKind::Aborted,
            reason: reason.to_string(),
            result_code: None,
            final_unit_action: None,
            redirect_server_address: None,
        });
        let service = Arc::clone(self);
        tokio::spawn(async move {
            service.abort_timer(&session).await;
            let unreported = match session.inner.metering {
                Metering::Local => session.unreported_secs(),
                Metering::External => 0,
            };
            service.send_terminate(&session, Some(0), unreported).await;
        });
        Some(dictionary::DIAMETER_SUCCESS)
    }

    // ── Timers ──────────────────────────────────────────────────────────

    async fn spawn_session_timer(
        self: &Arc<Self>,
        session: &CcCreditSession,
        first_wait: u32,
        initial_final: bool,
    ) {
        let service = Arc::clone(self);
        let task_session = session.clone();
        let handle = match session.inner.metering {
            Metering::Local => tokio::spawn(async move {
                service
                    .reauth_loop(task_session, first_wait, initial_final)
                    .await;
            }),
            Metering::External => tokio::spawn(async move {
                service.external_watch(task_session).await;
            }),
        };
        *session.inner.reauth_handle.lock().await = Some(handle);
    }

    /// External metering: restart the watch after a new grant.
    async fn restart_session_timer(self: &Arc<Self>, session: &CcCreditSession) {
        if session.inner.metering != Metering::External {
            return;
        }
        let service = Arc::clone(self);
        let task_session = session.clone();
        let handle = tokio::spawn(async move {
            service.external_watch(task_session).await;
        });
        if let Some(previous) = session.inner.reauth_handle.lock().await.replace(handle) {
            previous.abort();
        }
    }

    async fn external_watch(self: Arc<Self>, session: CcCreditSession) {
        external_watch_inner(session.clone()).await;
        // Reached only through the lifetime backstop.
        if session.is_open() && self.claim_stop(&session) {
            warn!(session_id = %session.inner.session_id,
                "ro: externally metered session exceeded max lifetime, terminating");
            session.emit(RoSessionEvent {
                kind: RoEventKind::Released,
                reason: "session lifetime exceeded".to_string(),
                result_code: None,
                final_unit_action: None,
                redirect_server_address: None,
            });
            self.send_terminate(&session, Some(CAUSE_CODE_SESSION_LIFETIME_EXCEEDED), 0)
                .await;
        }
    }

    /// The re-authorization loop of a locally metered session. Sleeps until
    /// the grant (less its threshold) or its Validity-Time is reached, or a RAR
    /// arrives; sends a CCR-UPDATE reporting the unreported usage; enforces
    /// teardown on denial or after the final units.
    async fn reauth_loop(
        self: Arc<Self>,
        session: CcCreditSession,
        first_wait: u32,
        initial_final: bool,
    ) {
        let mut wait = first_wait.max(MIN_REAUTH_SECS);
        // Set once the current grant is the last one: the *next* wake-up
        // consumes it and tears down, with no further CCR-UPDATE (RFC 8506
        // §5.6). A RAR in the meantime still asks — the OCS sends one after a
        // top-up.
        let mut is_final = initial_final;
        loop {
            let reauth_by_rar = tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(wait.max(MIN_REAUTH_SECS) as u64)) => false,
                _ = session.inner.wake.notified() => true,
            };
            if !session.is_open() {
                return;
            }
            if reauth_by_rar && !session.inner.reauth_requested.swap(false, Ordering::AcqRel) {
                // A stale wake-up with no RAR behind it: wait out the grant.
                continue;
            }
            if is_final && !reauth_by_rar {
                // The grant just consumed was the final one — cut now. Its
                // seconds are unreported, so the CCR-T's USU covers them once.
                self.enforce(&session, "credit exhausted (final unit)", None)
                    .await;
                return;
            }
            if session.inner.started_at.elapsed().as_secs() >= MAX_RO_SESSION_LIFETIME_SECS {
                if self.claim_stop(&session) {
                    warn!(session_id = %session.inner.session_id,
                        "ro: session exceeded max lifetime, disconnecting + terminating");
                    // Fail-closed: a session with no BYE must not run forever
                    // free of charge — disconnect it too, not just CCR-T.
                    self.fire_teardown(&session, "session lifetime exceeded");
                    session.emit(RoSessionEvent {
                        kind: RoEventKind::Released,
                        reason: "session lifetime exceeded".to_string(),
                        result_code: None,
                        final_unit_action: None,
                        redirect_server_address: None,
                    });
                    let unreported = session.unreported_secs();
                    self.send_terminate(
                        &session,
                        Some(CAUSE_CODE_SESSION_LIFETIME_EXCEEDED),
                        unreported,
                    )
                    .await;
                }
                return;
            }

            // Report what is chargeable and not yet reported, not the interval
            // just slept: under `charge_from: answer` the intervals before the
            // 200 OK are ring time and carry zero.
            let unreported = session.unreported_secs();
            let used = ServiceUnit {
                time_seconds: Some(unreported),
                ..Default::default()
            };
            let requested = session.requested_units();
            let record_number = session.next_cc_request_number();
            // Mid-call usage has to be attributable too. No Cause-Code: the
            // session has not ended, so there is no cause.
            let ims_data = session.charging_data_for("INVITE", None);
            let vcs_data = session.vcs_snapshot();
            let params = session.params(
                CcRequestType::Update,
                record_number,
                ims_data.as_ref(),
                vcs_data.as_ref(),
                requested.as_ref(),
                Some(&used),
            );

            let result = self.exchange_in(&session, &params).await;
            if result.is_ok() {
                // The Used-Service-Unit was answered by the OCS, so it is now
                // reported — the eventual CCR-TERMINATION reports only what
                // happened after it (avoids double-counting).
                session
                    .inner
                    .reported_secs
                    .fetch_add(unreported, Ordering::Relaxed);
            }
            match result {
                Ok(answer) if answer.is_success() => {
                    wait = reauth_after(&answer, session.inner.requested_seconds);
                    // This grant is the last one — consume it next cycle, then
                    // tear down. Any Final-Unit-Action: siphon has no way to
                    // redirect or restrict a voice call itself, so REDIRECT and
                    // RESTRICT_ACCESS end it too, and the owner is told which.
                    is_final = answer.final_unit_action.is_some();
                }
                Ok(answer) if answer.result_code == DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE => {
                    // Free of charge from here on — stop charging, leave the call up.
                    info!(session_id = %session.inner.session_id,
                        "ro: CCR-UPDATE returned CREDIT_CONTROL_NOT_APPLICABLE, call continues uncharged");
                    if self.claim_stop(&session) {
                        session.emit(RoSessionEvent {
                            kind: RoEventKind::Released,
                            reason: "credit control not applicable".to_string(),
                            result_code: Some(answer.result_code),
                            final_unit_action: None,
                            redirect_server_address: None,
                        });
                    }
                    return;
                }
                Ok(answer) => {
                    // 4012 / 4010 / other denial — disconnect the call. This
                    // interval's usage was already reported in the CCR-U above,
                    // so the CCR-T reports ~0 (no double-count).
                    let reason = if answer.result_code == DIAMETER_CREDIT_LIMIT_REACHED {
                        "credit limit reached"
                    } else {
                        "credit denied"
                    };
                    info!(session_id = %session.inner.session_id,
                        result_code = answer.result_code, "ro: CCR-UPDATE denied, tearing down");
                    self.enforce(&session, reason, Some(answer.result_code))
                        .await;
                    return;
                }
                Err(error) => {
                    // No answer from any server → Credit-Control-Failure-
                    // Handling, as the OCS last set it (RFC 8506 §5.7). The
                    // interval was NOT counted as reported, so the CCR-T
                    // re-reports it.
                    if session.failure_handling() != CCFH_CONTINUE {
                        warn!(session_id = %session.inner.session_id, error = %error,
                            "ro: CCR-UPDATE failed, fail-closed teardown");
                        self.enforce(&session, "ocs unreachable", None).await;
                        return;
                    }
                    warn!(session_id = %session.inner.session_id, error = %error,
                        "ro: CCR-UPDATE failed, fail-open (continue uncharged retry)");
                    wait = self.config.reauth_interval_secs.max(MIN_REAUTH_SECS);
                }
            }
        }
    }

    /// Disconnect the call, tell the owner and send CCR-TERMINATION (enforced
    /// teardown path).
    async fn enforce(&self, session: &CcCreditSession, reason: &str, result_code: Option<u32>) {
        if !self.claim_stop(session) {
            return;
        }
        let grant = session.grant();
        self.fire_teardown(session, reason);
        session.emit(RoSessionEvent {
            kind: RoEventKind::Released,
            reason: reason.to_string(),
            result_code,
            final_unit_action: grant.final_unit_action,
            redirect_server_address: None,
        });
        let unreported = session.unreported_secs();
        self.send_terminate(session, Some(CAUSE_CODE_CREDIT_EXHAUSTED), unreported)
            .await;
    }
}

/// External metering's watch: tell the owner to report when the grant's
/// Validity-Time runs out (RFC 8506 §5.1.2), once per grant, and return at the
/// lifetime backstop.
async fn external_watch_inner(session: CcCreditSession) {
    let lifetime = Duration::from_secs(MAX_RO_SESSION_LIFETIME_SECS);
    let remaining = lifetime.saturating_sub(session.inner.started_at.elapsed());
    let validity = session
        .grant()
        .validity_time
        .filter(|validity| *validity > 0)
        .map(|validity| Duration::from_secs(validity.max(MIN_REAUTH_SECS) as u64));
    let Some(wait) = validity.filter(|wait| *wait < remaining) else {
        tokio::time::sleep(remaining).await;
        return;
    };
    tokio::time::sleep(wait).await;
    if !session.is_open() {
        return;
    }
    session.emit(RoSessionEvent {
        kind: RoEventKind::Reauthorize,
        reason: "validity time expired".to_string(),
        result_code: None,
        final_unit_action: None,
        redirect_server_address: None,
    });
    // The owner's report brings a new grant, which restarts this watch.
    tokio::time::sleep(remaining.saturating_sub(wait)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::ro_test_support::{
        ccr_of_type, enabled_config, ims_information, mock_ocs_manager,
    };

    #[tokio::test]
    async fn initial_grant_opens_session_then_terminate_drains() {
        let (manager, _rx, _cap) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let baseline = service.active_session_count();

        for i in 0..25 {
            let decision = service
                .authorize_call(
                    SubscriberId::msisdn("+310000000001"),
                    ImsChargingData {
                        user_session_id: Some(format!("call-{i}")),
                        ..Default::default()
                    },
                    format!("call-{i}"),
                )
                .await;
            let session = match decision {
                ChargeDecision::Granted(Some(s)) => s,
                other => panic!("expected Granted, got {}", decision_label(&other)),
            };
            assert!(service.active_session_count() > baseline);
            service.terminate_call(&session, Some(0)).await;
        }
        assert_eq!(
            service.active_session_count(),
            baseline,
            "ro sessions must drain to baseline after completed calls"
        );
    }

    #[tokio::test]
    async fn granted_session_surfaces_grant_and_session_id() {
        // The three fields `call.ro_authorize()` returns to the script come off
        // the granted session: granted_time, session_id, last_result_code.
        let (manager, _rx, _cap) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let decision = service
            .authorize_call(
                SubscriberId::sip_uri("sip:alice@ims.example.org"),
                ImsChargingData::default(),
                "call-1".to_string(),
            )
            .await;
        let session = match decision {
            ChargeDecision::Granted(Some(s)) => s,
            other => panic!("expected Granted, got {}", decision_label(&other)),
        };
        assert_eq!(
            session.granted_time(),
            30,
            "granted_time must reflect the OCS CC-Time grant"
        );
        assert!(
            !session.session_id().is_empty(),
            "session_id must be populated for CCR-U/T continuity"
        );
        assert_eq!(session.last_result_code(), Some(2001));
        service.terminate_call(&session, Some(0)).await;
        assert_eq!(service.active_session_count(), 0);
    }

    #[tokio::test]
    async fn setup_denied_opens_no_session() {
        let (manager, _rx, _cap) =
            mock_ocs_manager(DIAMETER_CREDIT_LIMIT_REACHED, None, 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let decision = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData::default(),
                "c1".to_string(),
            )
            .await;
        assert!(matches!(decision, ChargeDecision::Denied(4012)));
        assert_eq!(service.active_session_count(), 0);
    }

    #[tokio::test]
    async fn credit_control_not_applicable_allows_uncharged() {
        let (manager, _rx, _cap) =
            mock_ocs_manager(DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE, None, 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let decision = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData::default(),
                "c1".to_string(),
            )
            .await;
        assert!(matches!(decision, ChargeDecision::AllowUncharged));
        assert_eq!(service.active_session_count(), 0);
    }

    #[tokio::test]
    async fn iec_event_granted_and_denied() {
        let (granted_mgr, _rx1, _cap1) = mock_ocs_manager(2001, None, 2001, None).await;
        let service = RoChargingService::new(granted_mgr, enabled_config());
        let ok = service
            .charge_event(
                SubscriberId::msisdn("+310000000001"),
                ro::SERVICE_CONTEXT_ID_SMS,
                None,
                Some(&SmsChargingData::default()),
            )
            .await;
        assert!(matches!(ok, ChargeDecision::Granted(None)));

        let (denied_mgr, _rx2, _cap2) =
            mock_ocs_manager(DIAMETER_CREDIT_LIMIT_REACHED, None, 2001, None).await;
        let service2 = RoChargingService::new(denied_mgr, enabled_config());
        let denied = service2
            .charge_event(
                SubscriberId::msisdn("+310000000001"),
                ro::SERVICE_CONTEXT_ID_SMS,
                None,
                Some(&SmsChargingData::default()),
            )
            .await;
        assert!(matches!(denied, ChargeDecision::Denied(4012)));
    }

    #[tokio::test(start_paused = true)]
    async fn reauth_denial_fires_teardown_and_drains() {
        // Grant at INITIAL, then the mock denies the first UPDATE → the re-auth
        // loop must fire the teardown hook exactly once and drain the session.
        // Paused clock so the grant sleep resolves without a real wait.
        let (manager, _rx, _cap) = mock_ocs_manager(
            2001,
            Some(MIN_REAUTH_SECS),
            DIAMETER_CREDIT_LIMIT_REACHED,
            None,
        )
        .await;
        let service = RoChargingService::new(manager, enabled_config());

        let torn_down = Arc::new(AtomicUsize::new(0));
        let hook_count = Arc::clone(&torn_down);
        service.set_teardown_hook(Arc::new(move |_call_id, _reason| {
            hook_count.fetch_add(1, Ordering::Relaxed);
        }));

        let decision = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData::default(),
                "c1".to_string(),
            )
            .await;
        assert!(matches!(decision, ChargeDecision::Granted(Some(_))));
        assert_eq!(service.active_session_count(), 1);

        // Let the paused clock advance past the grant so the UPDATE fires and
        // is denied; poll briefly for the background loop to enforce teardown.
        for _ in 0..50 {
            tokio::time::advance(Duration::from_secs(MIN_REAUTH_SECS as u64 + 1)).await;
            tokio::task::yield_now().await;
            if service.active_session_count() == 0 {
                break;
            }
        }
        assert_eq!(
            service.active_session_count(),
            0,
            "denied session must drain"
        );
        assert_eq!(
            torn_down.load(Ordering::Relaxed),
            1,
            "teardown hook must fire exactly once"
        );
    }

    fn denials_counter(result_code: &str) -> u64 {
        crate::metrics::metrics()
            .map(|metrics| {
                metrics
                    .ro_denials_total
                    .with_label_values(&[result_code])
                    .get()
            })
            .unwrap_or(0)
    }

    fn teardowns_counter(reason: &str) -> u64 {
        crate::metrics::metrics()
            .map(|metrics| {
                metrics
                    .ro_credit_teardowns_total
                    .with_label_values(&[reason])
                    .get()
            })
            .unwrap_or(0)
    }

    /// A refused call is a call that never happened, and until this counter
    /// existed it moved nothing: the CCR/CCA round trip succeeded, no SIP error
    /// counter fired, and the only trace was one `info!` line.
    /// 4010 END_USER_SERVICE_DENIED rather than the 4012 the tests above use:
    /// the metric registry is process-wide and these run in parallel, so a
    /// series another test also writes cannot carry an exact-delta assertion.
    const DIAMETER_END_USER_SERVICE_DENIED: u32 = 4010;

    #[tokio::test]
    async fn a_denied_setup_is_counted_under_its_result_code() {
        crate::metrics::init().ok();
        let before = denials_counter("4010");

        let (manager, _rx, _cap) =
            mock_ocs_manager(DIAMETER_END_USER_SERVICE_DENIED, None, 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let decision = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData::default(),
                "c1".to_string(),
            )
            .await;

        assert!(matches!(decision, ChargeDecision::Denied(4010)));
        assert_eq!(
            denials_counter("4010") - before,
            1,
            "a credit denial must be counted under the Result-Code that caused it"
        );
        // The denial opened no session, so the leak gate stays green.
        assert_eq!(service.active_session_count(), 0);
    }

    /// The teardown half: a call that was granted, ran, and was cut off mid-way
    /// when credit ran out. Distinct from a denial — one is a call that never
    /// started, the other a call the subscriber was already in.
    #[tokio::test(start_paused = true)]
    async fn a_credit_teardown_is_counted_under_its_reason() {
        crate::metrics::init().ok();
        // 4010 maps to the "credit denied" reason, which no other test emits —
        // 4012's "credit limit reached" is shared with the teardown test above.
        let before = teardowns_counter("credit_denied");

        let (manager, _rx, _cap) = mock_ocs_manager(
            2001,
            Some(MIN_REAUTH_SECS),
            DIAMETER_END_USER_SERVICE_DENIED,
            None,
        )
        .await;
        let service = RoChargingService::new(manager, enabled_config());
        service.set_teardown_hook(Arc::new(move |_call_id, _reason| {}));

        let decision = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData::default(),
                "c1".to_string(),
            )
            .await;
        assert!(matches!(decision, ChargeDecision::Granted(Some(_))));

        for _ in 0..50 {
            tokio::time::advance(Duration::from_secs(MIN_REAUTH_SECS as u64 + 1)).await;
            tokio::task::yield_now().await;
            if service.active_session_count() == 0 {
                break;
            }
        }

        assert_eq!(service.active_session_count(), 0, "session must drain");
        assert_eq!(
            teardowns_counter("credit_denied") - before,
            1,
            "a mid-call credit teardown must be counted under its reason"
        );
    }

    #[test]
    fn teardown_reasons_map_to_bounded_labels() {
        // Every reason string the enforcement paths actually pass.
        assert_eq!(
            teardown_reason_label("credit limit reached"),
            "credit_limit_reached"
        );
        assert_eq!(teardown_reason_label("credit denied"), "credit_denied");
        assert_eq!(
            teardown_reason_label("credit exhausted (final unit)"),
            "final_unit"
        );
        assert_eq!(
            teardown_reason_label("session lifetime exceeded"),
            "session_lifetime_exceeded"
        );
        assert_eq!(teardown_reason_label("ocs unreachable"), "ocs_unreachable");
        // Anything else collapses rather than minting a series, so adding a
        // reason string later cannot quietly grow the label set.
        assert_eq!(teardown_reason_label("something new"), "other");
    }

    fn decision_label(decision: &ChargeDecision) -> &'static str {
        match decision {
            ChargeDecision::Granted(_) => "Granted",
            ChargeDecision::Denied(_) => "Denied",
            ChargeDecision::AllowUncharged => "AllowUncharged",
        }
    }

    /// Concurrency gate: many CCR-INITIALs racing through one peer must each get
    /// a UNIQUE Session-Id (the bug where `new_session_id` read the hbh/e2e
    /// counters without reserving them collapsed concurrent calls into one OCS
    /// session). Also asserts the store drains after all terminate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sessions_get_unique_ids_and_drain() {
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());

        // Fire 40 authorizations concurrently.
        let mut handles = Vec::new();
        for i in 0..40 {
            let svc = Arc::clone(&service);
            handles.push(tokio::spawn(async move {
                svc.authorize_call(
                    SubscriberId::msisdn("+310000000001"),
                    ImsChargingData {
                        user_session_id: Some(format!("call-{i}")),
                        ..Default::default()
                    },
                    format!("call-{i}"),
                )
                .await
            }));
        }
        let mut sessions = Vec::new();
        for h in handles {
            if let ChargeDecision::Granted(Some(s)) = h.await.unwrap() {
                sessions.push(s);
            }
        }
        assert_eq!(sessions.len(), 40, "all 40 should be granted");

        // Every session-id is distinct (in the handles and on the wire).
        let ids: std::collections::HashSet<_> = sessions
            .iter()
            .map(|s| s.session_id().to_string())
            .collect();
        assert_eq!(
            ids.len(),
            40,
            "session-ids must be unique across concurrent calls"
        );
        let wire_ids: std::collections::HashSet<_> = captured
            .lock()
            .unwrap()
            .iter()
            .filter_map(|c| {
                c.get("Session-Id")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();
        assert_eq!(
            wire_ids.len(),
            40,
            "on-the-wire CCR Session-Ids must be unique too"
        );

        for s in &sessions {
            service.terminate_call(s, Some(0)).await;
        }
        assert_eq!(service.active_session_count(), 0, "all sessions must drain");
    }

    /// 100 sequential reserve→terminate cycles: the store returns to baseline
    /// every time and never reuses a Session-Id.
    #[tokio::test]
    async fn many_sequential_cycles_drain_with_unique_ids() {
        let (manager, _rx, _cap) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let decision = service
                .authorize_call(
                    SubscriberId::msisdn("+310000000001"),
                    ImsChargingData::default(),
                    format!("call-{i}"),
                )
                .await;
            let ChargeDecision::Granted(Some(session)) = decision else {
                panic!("cycle {i} not granted");
            };
            assert!(
                seen.insert(session.session_id().to_string()),
                "Session-Id reused at cycle {i}"
            );
            service.terminate_call(&session, Some(0)).await;
            assert_eq!(service.active_session_count(), 0, "must drain each cycle");
        }
    }

    /// The CCR-TERMINATION carries a Used-Service-Unit (RFC 8506 §5.6), shares
    /// the INITIAL's Session-Id, and uses the next CC-Request-Number.
    #[tokio::test]
    async fn terminate_carries_used_service_unit_and_continues_session() {
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let decision = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                ImsChargingData::default(),
                "c1".to_string(),
            )
            .await;
        let ChargeDecision::Granted(Some(session)) = decision else {
            panic!("not granted");
        };
        let sid = session.session_id().to_string();
        // Terminate immediately (before the 30s grant elapses → no CCR-UPDATE).
        service.terminate_call(&session, Some(0)).await;

        let ccrs = captured.lock().unwrap().clone();
        let terminate = ccrs
            .iter()
            .find(|c| c.get("CC-Request-Type").and_then(|v| v.as_u64()) == Some(3))
            .expect("a CCR-TERMINATION was sent");
        assert_eq!(
            terminate.get("Session-Id").and_then(|v| v.as_str()),
            Some(sid.as_str()),
            "CCR-T must reuse the INITIAL Session-Id"
        );
        assert_eq!(
            terminate.get("CC-Request-Number").and_then(|v| v.as_u64()),
            Some(1),
            "CCR-T request number is INITIAL(0)+1"
        );
        // Used-Service-Unit nested in the MSCC (rating_group is set) with a CC-Time.
        assert!(
            terminate
                .get("Multiple-Services-Credit-Control")
                .and_then(|m| m.get("Used-Service-Unit"))
                .and_then(|u| u.get("CC-Time"))
                .is_some(),
            "CCR-T must report a Used-Service-Unit CC-Time"
        );
    }
    // -----------------------------------------------------------------------
    // Service-Information on CCR-UPDATE / CCR-TERMINATION, and Cause-Code
    // -----------------------------------------------------------------------

    /// The IMS-Information a real call's CCR-INITIAL is built with.
    fn call_charging_data() -> ImsChargingData {
        ImsChargingData {
            calling_party: vec!["sip:+10000000001@ims.example.com".into()],
            called_party: Some("sip:+10000000002@ims.example.com".into()),
            sip_method: Some("INVITE".into()),
            ims_charging_identifier: Some("icid-value-1".into()),
            user_session_id: Some("call-1@ims.example.com".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn terminate_carries_ims_information_describing_the_call() {
        // CCR-TERMINATION used to go out with ims_data: None, so only the
        // Session-Id, the subscriber and the units reached the OCS — nothing
        // downstream could attribute the final record to an ICID or a party.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let ChargeDecision::Granted(Some(session)) = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                call_charging_data(),
                "c1".to_string(),
            )
            .await
        else {
            panic!("not granted");
        };
        service.terminate_call(&session, Some(0)).await;

        let ccrs = captured.lock().unwrap().clone();
        let terminate = ccr_of_type(&ccrs, 3);
        let ims = ims_information(&terminate).expect("CCR-T must carry IMS-Information");

        assert_eq!(
            ims.get("IMS-Charging-Identifier").and_then(|v| v.as_str()),
            Some("icid-value-1"),
        );
        assert_eq!(
            ims.get("User-Session-Id").and_then(|v| v.as_str()),
            Some("call-1@ims.example.com"),
        );
        assert_eq!(
            ims.get("Called-Party-Address").and_then(|v| v.as_str()),
            Some("sip:+10000000002@ims.example.com"),
        );
    }

    /// The Access-Network-Information of a call's CCR-INITIAL and
    /// CCR-TERMINATION as the mock OCS read them, for a call whose INVITE
    /// carried `P-Access-Network-Info`.
    async fn access_network_information_on_the_wire(
        enabled: bool,
    ) -> Vec<Option<serde_json::Value>> {
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(
            manager,
            RoConfig {
                access_network_information: enabled,
                ..enabled_config()
            },
        );
        let mut charging_data = call_charging_data();
        charging_data.access_network_information =
            vec!["3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100010000101".into()];
        let ChargeDecision::Granted(Some(session)) = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                charging_data,
                "c1".to_string(),
            )
            .await
        else {
            panic!("not granted");
        };
        service.terminate_call(&session, Some(0)).await;

        let ccrs = captured.lock().unwrap().clone();
        [1, 3]
            .into_iter()
            .map(|request_type| {
                ims_information(&ccr_of_type(&ccrs, request_type))
                    .expect("the CCR carries IMS-Information")
                    .get("Access-Network-Information")
                    .cloned()
            })
            .collect()
    }

    #[tokio::test]
    async fn access_network_information_is_withheld_from_the_ocs_by_default() {
        assert!(!RoConfig::default().access_network_information);
        assert_eq!(
            access_network_information_on_the_wire(false).await,
            vec![None, None]
        );
    }

    #[tokio::test]
    async fn access_network_information_reaches_the_ocs_when_asked_for() {
        // Our dictionary types the AVP OctetString, so it reads back as the
        // hex of the header text.
        let expected: String = "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100010000101"
            .bytes()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            access_network_information_on_the_wire(true).await,
            vec![
                Some(serde_json::Value::String(expected.clone())),
                Some(serde_json::Value::String(expected)),
            ]
        );
    }

    #[tokio::test]
    async fn terminate_carries_the_carrier_that_actually_took_the_call() {
        // Under LCR failover the winning carrier is not necessarily the one the
        // CCR-INITIAL was built for, so it is stamped on the session at answer
        // and has to reach the final record.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let ChargeDecision::Granted(Some(session)) = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                call_charging_data(),
                "c1".to_string(),
            )
            .await
        else {
            panic!("not granted");
        };

        // The INITIAL went out before any carrier was chosen.
        let initial = ccr_of_type(&captured.lock().unwrap().clone(), 1);
        assert!(
            ims_information(&initial)
                .and_then(|i| i.get("Trunk-Group-Id"))
                .is_none(),
            "no carrier is known yet at CCR-INITIAL",
        );

        session.set_outgoing_trunk_group("carrier-b");
        service.terminate_call(&session, Some(0)).await;

        let terminate = ccr_of_type(&captured.lock().unwrap().clone(), 3);
        // TS 32.299 §7.2.71 groups it under Trunk-Group-Id.
        assert_eq!(
            ims_information(&terminate)
                .and_then(|i| i.get("Trunk-Group-Id"))
                .and_then(|t| t.get("Outgoing-Trunk-Group-Id"))
                .and_then(|v| v.as_str()),
            Some("carrier-b"),
            "the final record must name the carrier that carried the call",
        );
    }

    #[tokio::test]
    async fn update_carries_ims_information_so_midcall_usage_is_attributable() {
        // A 5s grant so the re-auth loop fires an UPDATE quickly.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(1), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let ChargeDecision::Granted(Some(session)) = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                call_charging_data(),
                "c1".to_string(),
            )
            .await
        else {
            panic!("not granted");
        };
        session.set_outgoing_trunk_group("carrier-b");

        // MIN_REAUTH_SECS floors the grant at 5s; wait past one interval.
        tokio::time::sleep(Duration::from_secs(MIN_REAUTH_SECS as u64 + 2)).await;

        let ccrs = captured.lock().unwrap().clone();
        let update = ccr_of_type(&ccrs, 2);
        let ims = ims_information(&update).expect("CCR-U must carry IMS-Information");

        assert_eq!(
            ims.get("Trunk-Group-Id")
                .and_then(|t| t.get("Outgoing-Trunk-Group-Id"))
                .and_then(|v| v.as_str()),
            Some("carrier-b"),
        );
        assert_eq!(
            ims.get("IMS-Charging-Identifier").and_then(|v| v.as_str()),
            Some("icid-value-1"),
        );
        // No Cause-Code: the session has not ended, so there is no cause.
        assert!(
            ims.get("Cause-Code").is_none(),
            "a mid-call re-authorization has no termination cause to report",
        );

        service.terminate_call(&session, Some(0)).await;
    }

    /// Drive one call to CCR-TERMINATION with `cause` and read the Cause-Code
    /// the OCS saw.
    async fn cause_code_on_the_wire(cause: Option<i32>) -> Option<i64> {
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let ChargeDecision::Granted(Some(session)) = service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                call_charging_data(),
                "c1".to_string(),
            )
            .await
        else {
            panic!("not granted");
        };
        service.terminate_call(&session, cause).await;

        let terminate = ccr_of_type(&captured.lock().unwrap().clone(), 3);
        ims_information(&terminate)
            .and_then(|i| i.get("Cause-Code"))
            .and_then(|v| v.as_i64())
    }

    #[tokio::test]
    async fn a_hangup_a_busy_and_a_no_answer_are_distinguishable_on_the_wire() {
        // The point of the AVP: an OCS must be able to tell why a call ended.
        // The mapping is Rf's, so the two interfaces never disagree.
        use crate::diameter::rf::sip_status_to_cause_code;

        let normal = cause_code_on_the_wire(sip_status_to_cause_code(200)).await;
        let busy = cause_code_on_the_wire(sip_status_to_cause_code(486)).await;
        let no_answer = cause_code_on_the_wire(sip_status_to_cause_code(408)).await;
        let exhausted = cause_code_on_the_wire(Some(CAUSE_CODE_CREDIT_EXHAUSTED)).await;

        assert_eq!(normal, Some(0), "a normal hangup is cause 0");
        assert_eq!(busy, Some(486));
        assert_eq!(no_answer, Some(408));
        assert_eq!(exhausted, Some(402));

        let all = [normal, busy, no_answer, exhausted];
        let distinct: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(
            distinct.len(),
            all.len(),
            "all four must be distinguishable"
        );
    }

    #[tokio::test]
    async fn a_terminate_with_no_cause_omits_the_avp() {
        // `None` means "no cause to report" and must not be encoded as a 0 that
        // claims the call ended normally.
        assert_eq!(cause_code_on_the_wire(None).await, None);
    }
    // -----------------------------------------------------------------------
    // charge_from: the chargeable clock, and the answer-time CCR-UPDATE
    // -----------------------------------------------------------------------

    fn config_charging_from(charge_from: &str) -> RoConfig {
        RoConfig {
            charge_from: charge_from.to_string(),
            ..enabled_config()
        }
    }

    async fn granted_session(service: &Arc<RoChargingService>) -> CcCreditSession {
        match service
            .authorize_call(
                SubscriberId::msisdn("+310000000001"),
                call_charging_data(),
                "c1".to_string(),
            )
            .await
        {
            ChargeDecision::Granted(Some(session)) => session,
            other => panic!("expected Granted, got {}", decision_label(&other)),
        }
    }

    #[test]
    fn charge_from_parses_and_defaults_to_answer() {
        assert_eq!(ChargeFrom::from_config("answer"), ChargeFrom::Answer);
        assert_eq!(ChargeFrom::from_config("invite"), ChargeFrom::Invite);
        assert_eq!(ChargeFrom::from_config("ANSWER"), ChargeFrom::Answer);
        assert_eq!(ChargeFrom::from_config(" invite "), ChargeFrom::Invite);
        // An unrecognised value must not silently start billing ring time.
        assert_eq!(ChargeFrom::from_config("nonsense"), ChargeFrom::Answer);
        assert_eq!(ChargeFrom::from_config(""), ChargeFrom::Answer);
        // And the config default is the spec-correct one.
        assert_eq!(
            ChargeFrom::from_config(&RoConfig::default().charge_from),
            ChargeFrom::Answer
        );
    }

    #[tokio::test]
    async fn a_call_that_rings_and_is_never_answered_reports_zero_usage() {
        // The defect this closes: `started_at` was stamped at the reservation,
        // before any carrier was dialled, and every reported figure was
        // `started_at.elapsed()`. With two carriers at timeout_secs: 12, 24
        // seconds of a 30-second grant could be gone before the callee picked
        // up — and an unanswered call could report a full grant of used time.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("answer"));
        let session = granted_session(&service).await;

        // Ring for a while. `report_answer` is never called.
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(session.chargeable_secs(), 0, "ring time is not chargeable");

        service.terminate_call(&session, Some(0)).await;

        let terminate = ccr_of_type(&captured.lock().unwrap().clone(), 3);
        assert_eq!(
            terminate
                .get("Multiple-Services-Credit-Control")
                .and_then(|m| m.get("Used-Service-Unit"))
                .and_then(|u| u.get("CC-Time"))
                .and_then(|v| v.as_u64()),
            Some(0),
            "an unanswered call has no chargeable duration",
        );
    }

    #[tokio::test]
    async fn charge_from_answer_counts_from_the_answer_not_the_reservation() {
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("answer"));
        let session = granted_session(&service).await;

        // Ring, then answer, then talk.
        tokio::time::sleep(Duration::from_secs(2)).await;
        service.report_answer(&session).await;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let chargeable = session.chargeable_secs();
        assert!(
            chargeable <= 1,
            "only the answered span is chargeable, got {chargeable}s after 2s ringing + 1s talking",
        );

        service.terminate_call(&session, Some(0)).await;
        let terminate = ccr_of_type(&captured.lock().unwrap().clone(), 3);
        let reported = terminate
            .get("Multiple-Services-Credit-Control")
            .and_then(|m| m.get("Used-Service-Unit"))
            .and_then(|u| u.get("CC-Time"))
            .and_then(|v| v.as_u64())
            .expect("CCR-T reports a CC-Time");
        assert!(
            reported <= 1,
            "reported {reported}s, expected only the talk time"
        );
    }

    #[tokio::test]
    async fn charge_from_invite_preserves_the_previous_behaviour() {
        let (manager, _rx, _captured) = mock_ocs_manager(2001, Some(30), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("invite"));
        let session = granted_session(&service).await;

        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(
            session.chargeable_secs() >= 2,
            "charge_from: invite bills from the reservation, ring time included",
        );

        service.terminate_call(&session, Some(0)).await;
    }

    #[tokio::test]
    async fn answer_sends_a_ccr_update_carrying_both_timestamps() {
        // TS 32.299 §7.2.97: Time-Stamps with SIP-Request-Timestamp (the
        // INVITE) and SIP-Response-Timestamp (the answer). Without a request at
        // the 200 OK an OCS cannot tell when charging started at all.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(300), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("answer"));
        let session = granted_session(&service).await;

        service.report_answer(&session).await;

        let ccrs = captured.lock().unwrap().clone();
        let update = ccr_of_type(&ccrs, 2);
        let timestamps = ims_information(&update)
            .and_then(|i| i.get("Time-Stamps"))
            .expect("the answer CCR-UPDATE must carry Time-Stamps");

        assert!(
            timestamps.get("SIP-Request-Timestamp").is_some(),
            "SIP-Request-Timestamp missing: {timestamps}",
        );
        assert!(
            timestamps.get("SIP-Response-Timestamp").is_some(),
            "SIP-Response-Timestamp missing: {timestamps}",
        );

        service.terminate_call(&session, Some(0)).await;
    }

    #[tokio::test]
    async fn a_retransmitted_answer_neither_restarts_the_clock_nor_resends() {
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(300), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("answer"));
        let session = granted_session(&service).await;

        service.report_answer(&session).await;
        let first = session.answered_at();
        tokio::time::sleep(Duration::from_secs(1)).await;
        service.report_answer(&session).await;
        service.report_answer(&session).await;

        assert_eq!(
            session.answered_at(),
            first,
            "a retransmitted 200 OK must not restart the chargeable clock",
        );
        let updates = captured
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.get("CC-Request-Type").and_then(|v| v.as_u64()) == Some(2))
            .count();
        assert_eq!(updates, 1, "exactly one answer CCR-UPDATE, got {updates}");

        service.terminate_call(&session, Some(0)).await;
    }

    #[tokio::test]
    async fn answer_on_an_already_stopped_session_is_a_no_op() {
        // A 2xx racing a teardown must not reopen charging on a closed session.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(300), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("answer"));
        let session = granted_session(&service).await;

        service.terminate_call(&session, Some(0)).await;
        service.report_answer(&session).await;

        let updates = captured
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.get("CC-Request-Type").and_then(|v| v.as_u64()) == Some(2))
            .count();
        assert_eq!(updates, 0, "no CCR-UPDATE after the session was stopped");
    }

    #[tokio::test]
    async fn reported_usage_is_never_double_counted_across_update_and_terminate() {
        // Usage is reported as a delta against what the OCS has already
        // acknowledged, so an interval reported by a CCR-UPDATE must not appear
        // again in the CCR-TERMINATION.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(1), 2001, None).await;
        let service = RoChargingService::new(manager, config_charging_from("answer"));
        let session = granted_session(&service).await;
        service.report_answer(&session).await;

        // Past one re-auth interval (floored at MIN_REAUTH_SECS).
        tokio::time::sleep(Duration::from_secs(MIN_REAUTH_SECS as u64 + 2)).await;
        let total_chargeable = session.chargeable_secs();
        service.terminate_call(&session, Some(0)).await;

        let ccrs = captured.lock().unwrap().clone();
        let sum: u64 = ccrs
            .iter()
            .filter(|c| {
                matches!(
                    c.get("CC-Request-Type").and_then(|v| v.as_u64()),
                    Some(2) | Some(3)
                )
            })
            .filter_map(|c| {
                c.get("Multiple-Services-Credit-Control")
                    .and_then(|m| m.get("Used-Service-Unit"))
                    .and_then(|u| u.get("CC-Time"))
                    .and_then(|v| v.as_u64())
            })
            .sum();

        assert!(
            sum <= total_chargeable as u64 + 1,
            "reported {sum}s across all records but only {total_chargeable}s was chargeable",
        );
    }

    /// A call that reserved credit and then never dialled anything.
    ///
    /// `call.ro_authorize()` reserves *before* the B-leg is connected, so a
    /// routing decision that turns out to be undialable — every gateway group
    /// of an LCR answer unresolved, or no fork branch that could be sent —
    /// leaves a live session with no dialogue behind it. Two dispatcher paths
    /// used to answer the A-leg `503` and drop the call without releasing it,
    /// and what the OCS then saw was a call that was live and never ended:
    /// reserved credit never released, and a CCR-UPDATE carrying zero used
    /// units every re-auth interval, against nobody.
    ///
    /// The wire shape a released one has to have: `INITIAL` then `TERMINATION`,
    /// nothing in between and nothing after, carrying the status the A-leg was
    /// actually sent and no chargeable time.
    #[tokio::test]
    async fn a_reservation_released_before_any_leg_reports_the_status_the_caller_got() {
        use crate::diameter::rf::sip_status_to_cause_code;

        // A 1-second grant, so the re-auth loop is armed on the shortest
        // cadence it can run (floored at MIN_REAUTH_SECS) — if the release did
        // not disarm it, the sleep below is long enough for it to fire.
        let (manager, _rx, captured) = mock_ocs_manager(2001, Some(1), 2001, None).await;
        let service = RoChargingService::new(manager, enabled_config());
        let baseline = service.active_session_count();
        let session = granted_session(&service).await;

        // No dial, no ring, no answer: straight to the 503 the A-leg gets.
        service
            .terminate_call(&session, sip_status_to_cause_code(503))
            .await;
        tokio::time::sleep(Duration::from_secs(MIN_REAUTH_SECS as u64 + 2)).await;

        let ccrs = captured.lock().unwrap().clone();
        let types: Vec<Option<u64>> = ccrs
            .iter()
            .map(|c| c.get("CC-Request-Type").and_then(|v| v.as_u64()))
            .collect();
        assert_eq!(
            types,
            vec![Some(1), Some(3)],
            "the OCS must see exactly INITIAL then TERMINATION — a CCR-UPDATE \
             here is the re-auth timer billing a call that never had a leg",
        );

        let terminate = ccr_of_type(&ccrs, 3);
        assert_eq!(
            ims_information(&terminate)
                .and_then(|i| i.get("Cause-Code"))
                .and_then(|v| v.as_i64()),
            Some(503),
            "the cause is the status the A-leg was answered with, from the same \
             mapping Rf's ACR-STOP uses, so the two interfaces cannot disagree",
        );
        assert_eq!(
            terminate
                .get("Multiple-Services-Credit-Control")
                .and_then(|m| m.get("Used-Service-Unit"))
                .and_then(|u| u.get("CC-Time"))
                .and_then(|v| v.as_u64()),
            Some(0),
            "nothing was ever connected, so nothing is chargeable",
        );
        assert_eq!(
            service.active_session_count(),
            baseline,
            "the reservation must be released, not just reported on",
        );
    }
}

#[cfg(test)]
#[path = "ro_session_tests.rs"]
mod session_tests;
