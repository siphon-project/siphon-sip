//! Runtime helper that bridges siphon's B2BUA / proxy lifecycle to Ro online
//! charging (Diameter Credit-Control, RFC 8506 / 3GPP TS 32.299). The online
//! analogue of [`super::rf_service`].
//!
//! Two flows:
//!   * **SCUR** (voice) — [`RoChargingService::authorize_call`] reserves credit
//!     at setup (CCR-INITIAL); on grant a per-session Tokio timer re-authorizes
//!     (CCR-UPDATE) on a two-clock cadence and **disconnects the call** (via the
//!     teardown hook) when the OCS refuses further credit or sends a
//!     Final-Unit-Indication. [`RoChargingService::terminate_call`] sends
//!     CCR-TERMINATION on BYE.
//!   * **IEC** (SMS/RCS) — [`RoChargingService::charge_event`] does a one-shot
//!     CCR-EVENT (DIRECT_DEBITING) before delivery; no session, no timer.
//!
//! The mechanism (CCR/CCA state machine, timer, enforcement, session store) is
//! entirely Rust-side; policy (which subscriber, rating group, denial response)
//! is the caller's / the script's.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::RoConfig;
use crate::diameter::dictionary;
use crate::diameter::peer::DiameterPeer;
use crate::diameter::ro::{
    self, CcRequestType, CreditControlParams, ImsChargingData, NodeFunctionality, ServiceUnit,
    SmsChargingData, SubscriberId, REQUESTED_ACTION_DIRECT_DEBITING,
};
use crate::diameter::DiameterManager;

/// RFC 8506 §9.1 result codes relevant to charging enforcement.
/// DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE — grant the service free of charge,
/// end the CC session, do NOT deny.
const DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE: u32 = 4011;
const DIAMETER_CREDIT_LIMIT_REACHED: u32 = 4012;
/// Final-Unit-Action TERMINATE (RFC 8506 §8.35).
const FINAL_UNIT_ACTION_TERMINATE: u32 = 0;

/// IMS-Information `Cause-Code` (TS 32.299 §7.2.35) for a call siphon cut
/// because the OCS refused further credit.
///
/// The convention is Rf's, shared via [`crate::diameter::rf::sip_status_to_cause_code`]:
/// a successful end is `0`, anything else is the negated SIP status. `402
/// Payment Required` is the status siphon already answers when the OCS denies
/// at setup, so an out-of-credit teardown reports the same cause a denied setup
/// does — the OCS sees one code for "no credit", whenever it ran out.
const CAUSE_CODE_CREDIT_EXHAUSTED: i32 = -402;

/// `Cause-Code` for a session released by the max-lifetime backstop: no BYE
/// ever arrived, so this is a timeout, reported as `408 Request Timeout`.
const CAUSE_CODE_SESSION_LIFETIME_EXCEEDED: i32 = -408;

/// Never re-authorize faster than this, so a pathological small grant can't
/// hot-loop the OCS.
const MIN_REAUTH_SECS: u32 = 5;
/// Backstop: an abandoned session (no BYE, no session-timer) releases after
/// this long instead of re-authorizing forever.
const MAX_RO_SESSION_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// Hook the dispatcher installs so the Rust-side re-auth loop can disconnect a
/// live call from a background task. `(sip_call_id, reason)`.
///
/// Ro enforcement is **B2BUA-only** (see [`RoChargingService`]): the target is
/// always a tracked B2BUA call identified by its SIP Call-ID. There is no
/// proxy-mode teardown — a P-CSCF/proxy cannot own and cut the session, which is
/// exactly why 3GPP triggers online charging at the AS, not the P-CSCF.
pub type RoTeardownHook = Arc<dyn Fn(&str, &str) + Send + Sync>;

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

/// Per-call credit-control session (SCUR). Cloneable handle over `Arc` inner
/// state so the re-auth timer, the store and the BYE path can share it.
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
    /// SIP Call-ID of the B2BUA call to disconnect on credit exhaustion.
    sip_call_id: String,
    // Context needed to build UPDATE / TERMINATION without the caller re-supplying it.
    peer: Arc<DiameterPeer>,
    subscriber: SubscriberId,
    service_context_id: String,
    rating_group: Option<u32>,
    service_identifier: Option<u32>,
    requested_seconds: u32,
    /// The `ImsChargingData` built at CCR-INITIAL, carried on the session so
    /// every later request in it can describe the same call.
    ///
    /// CCR-UPDATE and CCR-TERMINATION used to send `ims_data: None`, so only
    /// the Session-Id, the subscriber and the units went down the pipe. A
    /// charging backend could not attribute mid-call usage or the final record
    /// to a carrier, an ICID or a calling/called party — and with LCR failover
    /// the carrier on the record is the one that actually carried the call, so
    /// it cannot be inferred from the INITIAL either.
    ///
    /// A `std::sync::Mutex` rather than a `tokio` one: it is only ever held to
    /// clone the value out, never across an await.
    ims_data: std::sync::Mutex<ImsChargingData>,
    started_at: Instant,
    /// The OCS's first-grant CC-Time (seconds) — surfaced to the script gate as
    /// `granted_time` so it can log / decide on the reserved quota.
    initial_grant: u32,
    /// Seconds already reported to the OCS via an *answered* CCR-UPDATE
    /// Used-Service-Unit. CCR-TERMINATION reports only `elapsed - reported`
    /// (the unreported remainder), so the last interval is never double-counted.
    reported_secs: AtomicU32,
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

    fn next_cc_request_number(&self) -> u32 {
        self.inner.cc_request_number.fetch_add(1, Ordering::Relaxed)
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
        let mut data = match self.inner.ims_data.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        data.sip_method = Some(sip_method.to_string());
        data.cause_code = cause_code;
        // Time-Stamps describes *this* record's trigger, not the INVITE the
        // INITIAL already reported (TS 32.299 §7.2.183) — carrying the setup
        // instant forward would leave a record whose Event-Type says BYE and
        // whose request timestamp is minutes older.
        let now = std::time::SystemTime::now();
        data.request_timestamp = Some(now);
        data.response_timestamp = Some(now);
        Some(data)
    }

    /// Record the carrier that actually carried the call, as
    /// `Outgoing-Trunk-Group-Id` (TS 32.299 §7.2.71).
    ///
    /// Load-bearing under LCR failover: the carrier on the final record is the
    /// one that answered, which is not necessarily the first one tried, so it
    /// cannot be inferred from the CCR-INITIAL.
    pub fn set_outgoing_trunk_group(&self, carrier_id: &str) {
        let mut guard = match self.inner.ims_data.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.outgoing_trunk_group_id = Some(carrier_id.to_string());
    }
}

/// Online-charging service. Holds the OCS peer resolution, the live-session
/// count, and the teardown hook.
///
/// **B2BUA-only.** Ro enforcement (reserve → re-authorize → disconnect the call
/// on credit exhaustion) requires owning and being able to tear down the
/// session — a B2BUA capability, and the reason 3GPP triggers online charging
/// at the AS/MMTel-AS, not the P-CSCF. There is no proxy-mode auto-emit or
/// teardown; run the charging siphon as a B2BUA (e.g. an MMTel-AS on ISC).
pub struct RoChargingService {
    manager: Arc<DiameterManager>,
    config: RoConfig,
    node_functionality: Option<NodeFunctionality>,
    active_sessions: Arc<AtomicUsize>,
    teardown_hook: StdMutex<Option<RoTeardownHook>>,
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
        Arc::new(Self {
            manager,
            config,
            node_functionality,
            active_sessions: Arc::new(AtomicUsize::new(0)),
            teardown_hook: StdMutex::new(None),
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
        if let Ok(mut guard) = self.teardown_hook.lock() {
            *guard = Some(hook);
        }
    }

    /// Number of live credit-control sessions — the per-module leak gate.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions.load(Ordering::Relaxed)
    }

    fn track_session_started(&self) {
        self.active_sessions.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = crate::metrics::metrics() {
            metrics.ro_sessions.inc();
        }
    }

    /// Flip `session` to stopped exactly once and release its slot from the
    /// count/gauge. Returns `true` only for the caller that won the race.
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
        }
        won
    }

    fn fire_teardown(&self, sip_call_id: &str, reason: &str) {
        let hook = self.teardown_hook.lock().ok().and_then(|g| g.clone());
        match hook {
            Some(hook) => hook(sip_call_id, reason),
            None => warn!(
                call_id = %sip_call_id,
                "ro: credit exhausted but no teardown hook installed; call not disconnected"
            ),
        }
    }

    fn pick_peer(&self) -> Option<Arc<DiameterPeer>> {
        if let Some(name) = self.config.peer.as_deref() {
            if let Some(client) = self.manager.client(name) {
                return Some(client.peer().clone());
            }
            warn!(peer = %name, "ro: configured OCS peer not connected, falling back to any peer");
        }
        self.manager.any_client().map(|c| c.peer().clone())
    }

    /// Requested-Service-Unit for a voice reservation. `None` when
    /// `requested_seconds == 0` (empty RSU — let the OCS decide the quota).
    fn requested_units(&self) -> Option<ServiceUnit> {
        (self.config.requested_seconds > 0).then(|| ServiceUnit {
            time_seconds: Some(self.config.requested_seconds),
            ..Default::default()
        })
    }

    fn fail_closed(&self) -> bool {
        !self.config.on_ocs_failure.eq_ignore_ascii_case("continue")
    }

    /// SCUR: reserve credit at call setup (CCR-INITIAL). On grant, a session is
    /// created, the re-auth timer armed, and the handle returned for the caller
    /// to store (so BYE / enforced teardown can find it). `sip_call_id` is the
    /// B2BUA call's SIP Call-ID used to disconnect it on credit exhaustion.
    pub async fn authorize_call(
        self: &Arc<Self>,
        subscriber: SubscriberId,
        mut ims_data: ImsChargingData,
        sip_call_id: String,
    ) -> ChargeDecision {
        if !self.config.enabled {
            return ChargeDecision::AllowUncharged;
        }
        let Some(peer) = self.pick_peer() else {
            return if self.fail_closed() {
                ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
            } else {
                ChargeDecision::AllowUncharged
            };
        };
        if ims_data.node_functionality.is_none() {
            ims_data.node_functionality = self.node_functionality;
        }

        let requested = self.requested_units();
        let params = CreditControlParams {
            request_type: CcRequestType::Initial,
            request_number: 0,
            subscriber: &subscriber,
            service_context_id: &self.config.service_context_id,
            session_id: None,
            ims_data: Some(&ims_data),
            sms_data: None,
            requested_units: requested.as_ref(),
            used_units: None,
            rating_group: self.config.rating_group,
            service_identifier: self.config.service_identifier,
            requested_action: None,
            multiple_services_indicator: true,
        };

        let answer = match ro::send_ccr(&peer, &params).await {
            Ok(answer) => answer,
            Err(error) => {
                warn!(error = %error, "ro: CCR-INITIAL failed");
                return if self.fail_closed() {
                    ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
                } else {
                    ChargeDecision::AllowUncharged
                };
            }
        };

        if answer.result_code == DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE {
            // Free of charge — no session, call proceeds unmonitored.
            info!("ro: CCR-INITIAL returned CREDIT_CONTROL_NOT_APPLICABLE, call proceeds uncharged");
            return ChargeDecision::AllowUncharged;
        }
        if !answer.is_success() {
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

        let grant_secs = grant_from(&answer, self.config.reauth_interval_secs);
        let session = CcCreditSession {
            inner: Arc::new(CcSessionInner {
                session_id,
                cc_request_number: AtomicU32::new(1),
                stopped: AtomicU32::new(0),
                reauth_handle: Mutex::new(None),
                last_result_code: AtomicU32::new(answer.result_code),
                sip_call_id,
                peer,
                subscriber,
                service_context_id: self.config.service_context_id.clone(),
                rating_group: self.config.rating_group,
                service_identifier: self.config.service_identifier,
                requested_seconds: self.config.requested_seconds,
                ims_data: std::sync::Mutex::new(ims_data),
                started_at: Instant::now(),
                initial_grant: grant_secs,
                reported_secs: AtomicU32::new(0),
            }),
        };
        self.track_session_started();
        // If the OCS already flagged this (initial) grant Final-Unit-Action =
        // TERMINATE — the low-balance case where the whole balance fits in one
        // grant — consume it, then cut, without ever sending a CCR-UPDATE.
        let initial_final = answer.final_unit_action == Some(FINAL_UNIT_ACTION_TERMINATE);
        self.spawn_reauth_timer(&session, grant_secs, initial_final).await;

        info!(
            session_id = %session.inner.session_id,
            grant_secs,
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
        };
        match ro::send_ccr(&peer, &params).await {
            Ok(answer) if answer.is_success() => {
                debug!("ro: CCR-EVENT (IEC) debited");
                ChargeDecision::Granted(None)
            }
            Ok(answer) => {
                info!(result_code = answer.result_code, "ro: CCR-EVENT (IEC) denied");
                ChargeDecision::Denied(answer.result_code)
            }
            Err(error) => {
                warn!(error = %error, "ro: CCR-EVENT (IEC) failed");
                if self.fail_closed() {
                    ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
                } else {
                    ChargeDecision::AllowUncharged
                }
            }
        }
    }

    /// Send CCR-TERMINATION for a session (BYE path). Idempotent — a session
    /// already stopped by the enforced-teardown path is a no-op.
    /// `cause_code` is the IMS-Information `Cause-Code` for the record
    /// (TS 32.299 §7.2.35), in the same negative-SIP convention Rf's ACR-STOP
    /// uses: `Some(0)` for a normal hangup, `Some(-486)` for a busy, and so on.
    /// Derive it with [`crate::diameter::rf::sip_status_to_cause_code`] so the
    /// two interfaces never disagree about why a call ended. `None` omits the
    /// AVP, for a teardown with no cause to report.
    pub async fn terminate_call(&self, session: &CcCreditSession, cause_code: Option<i32>) {
        if !self.claim_stop(session) {
            return;
        }
        if let Some(handle) = session.inner.reauth_handle.lock().await.take() {
            handle.abort();
        }
        self.send_terminate(session, cause_code).await;
    }

    /// Build + send a CCR-TERMINATION reporting the *unreported* usage
    /// (`elapsed - already-reported`, RFC 8506 §5.6). Does not touch the stopped
    /// flag (callers use `claim_stop` first).
    async fn send_terminate(&self, session: &CcCreditSession, cause_code: Option<i32>) {
        let elapsed = session.inner.started_at.elapsed().as_secs() as u32;
        let reported = session.inner.reported_secs.load(Ordering::Relaxed);
        let used = ServiceUnit {
            time_seconds: Some(elapsed.saturating_sub(reported)),
            ..Default::default()
        };
        let record_number = session.next_cc_request_number();
        // Describe the call on the final record too, not just on the INITIAL:
        // without this the CCR-T carried only Session-Id, subscriber and units,
        // so nothing downstream could attribute the record to a carrier, an
        // ICID or a calling/called party.
        let ims_data = session.charging_data_for("BYE", cause_code);
        let params = CreditControlParams {
            request_type: CcRequestType::Termination,
            request_number: record_number,
            subscriber: &session.inner.subscriber,
            service_context_id: &session.inner.service_context_id,
            session_id: Some(&session.inner.session_id),
            ims_data: ims_data.as_ref(),
            sms_data: None,
            requested_units: None,
            used_units: Some(&used),
            rating_group: session.inner.rating_group,
            service_identifier: session.inner.service_identifier,
            requested_action: None,
            multiple_services_indicator: false,
        };
        match ro::send_ccr(&session.inner.peer, &params).await {
            Ok(answer) => {
                session
                    .inner
                    .last_result_code
                    .store(answer.result_code, Ordering::Relaxed);
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

    async fn spawn_reauth_timer(
        self: &Arc<Self>,
        session: &CcCreditSession,
        initial_grant: u32,
        initial_final: bool,
    ) {
        let service = Arc::clone(self);
        let task_session = session.clone();
        let handle = tokio::spawn(async move {
            service.reauth_loop(task_session, initial_grant, initial_final).await;
        });
        *session.inner.reauth_handle.lock().await = Some(handle);
    }

    /// The two-clock re-authorization loop. Sleeps the granted quota, sends a
    /// CCR-UPDATE reporting the elapsed usage, and enforces teardown on denial
    /// or Final-Unit-Indication.
    async fn reauth_loop(
        self: Arc<Self>,
        session: CcCreditSession,
        initial_grant: u32,
        initial_final: bool,
    ) {
        let mut grant = initial_grant.max(MIN_REAUTH_SECS);
        // Set once the current grant is the last one (Final-Unit-Action =
        // TERMINATE): the *next* wake-up consumes it and tears down, with no
        // further CCR-UPDATE (RFC 8506 §5.6).
        let mut is_final = initial_final;
        loop {
            let sleep_secs = grant.max(MIN_REAUTH_SECS);
            tokio::time::sleep(Duration::from_secs(sleep_secs as u64)).await;
            if session.inner.stopped.load(Ordering::Relaxed) != 0 {
                return;
            }
            if is_final {
                // The grant just consumed was the final one — cut now. Its
                // seconds are unreported, so the CCR-T's USU covers them once.
                self.enforce(&session, "credit exhausted (final unit)").await;
                return;
            }
            if session.inner.started_at.elapsed().as_secs() >= MAX_RO_SESSION_LIFETIME_SECS {
                if self.claim_stop(&session) {
                    warn!(session_id = %session.inner.session_id,
                        "ro: session exceeded max lifetime, disconnecting + terminating");
                    // Fail-closed: a session with no BYE must not run forever
                    // free of charge — disconnect it too, not just CCR-T.
                    self.fire_teardown(&session.inner.sip_call_id, "session lifetime exceeded");
                    self.send_terminate(&session, Some(CAUSE_CODE_SESSION_LIFETIME_EXCEEDED))
                        .await;
                }
                return;
            }

            let used = ServiceUnit {
                time_seconds: Some(sleep_secs),
                ..Default::default()
            };
            let requested = (session.inner.requested_seconds > 0).then(|| ServiceUnit {
                time_seconds: Some(session.inner.requested_seconds),
                ..Default::default()
            });
            let record_number = session.next_cc_request_number();
            // Mid-call usage has to be attributable too — an OCS that cannot
            // tell which carrier a re-authorization belongs to cannot rate it.
            // No Cause-Code: the session has not ended, so there is no cause.
            let ims_data = session.charging_data_for("INVITE", None);
            let params = CreditControlParams {
                request_type: CcRequestType::Update,
                request_number: record_number,
                subscriber: &session.inner.subscriber,
                service_context_id: &session.inner.service_context_id,
                session_id: Some(&session.inner.session_id),
                ims_data: ims_data.as_ref(),
                sms_data: None,
                requested_units: requested.as_ref(),
                used_units: Some(&used),
                rating_group: session.inner.rating_group,
                service_identifier: session.inner.service_identifier,
                requested_action: None,
                multiple_services_indicator: false,
            };

            let result = ro::send_ccr(&session.inner.peer, &params).await;
            if result.is_ok() {
                // The Used-Service-Unit for this interval was answered by the
                // OCS, so it's now reported — the eventual CCR-TERMINATION
                // reports only what happened after it (avoids double-counting).
                session
                    .inner
                    .reported_secs
                    .fetch_add(sleep_secs, Ordering::Relaxed);
            }
            match result {
                Ok(answer) if answer.is_success() => {
                    session
                        .inner
                        .last_result_code
                        .store(answer.result_code, Ordering::Relaxed);
                    grant = grant_from(&answer, session.inner.requested_seconds);
                    if answer.final_unit_action == Some(FINAL_UNIT_ACTION_TERMINATE) {
                        // This grant is the last one — consume it next cycle,
                        // then tear down (no more CCR-UPDATE, RFC 8506 §5.6).
                        is_final = true;
                    }
                }
                Ok(answer)
                    if answer.result_code == DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE =>
                {
                    // Free of charge from here on — stop charging, leave the call up.
                    info!(session_id = %session.inner.session_id,
                        "ro: CCR-UPDATE returned CREDIT_CONTROL_NOT_APPLICABLE, call continues uncharged");
                    self.claim_stop(&session);
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
                    self.enforce(&session, reason).await;
                    return;
                }
                Err(error) => {
                    // Tx timeout / transport error → Credit-Control-Failure-Handling.
                    // The interval was NOT counted as reported (the CCR-U wasn't
                    // answered), so the CCR-T re-reports it.
                    if self.fail_closed() {
                        warn!(session_id = %session.inner.session_id, error = %error,
                            "ro: CCR-UPDATE failed, fail-closed teardown");
                        self.enforce(&session, "ocs unreachable").await;
                        return;
                    }
                    warn!(session_id = %session.inner.session_id, error = %error,
                        "ro: CCR-UPDATE failed, fail-open (continue uncharged retry)");
                    // Fail-open: keep the call, retry next cycle at the fallback cadence.
                    grant = self.config.reauth_interval_secs.max(MIN_REAUTH_SECS);
                }
            }
        }
    }

    /// Disconnect the call and send CCR-TERMINATION (enforced teardown path).
    async fn enforce(&self, session: &CcCreditSession, reason: &str) {
        if !self.claim_stop(session) {
            return;
        }
        self.fire_teardown(&session.inner.sip_call_id, reason);
        self.send_terminate(session, Some(CAUSE_CODE_CREDIT_EXHAUSTED))
            .await;
    }
}

/// Re-authorization cadence from a CCA: prefer the granted CC-Time, then
/// Validity-Time, then the configured fallback. The two clocks collapse to the
/// tighter deadline here (a full split of quota-vs-validity is a follow-up).
fn grant_from(answer: &ro::CreditControlAnswer, fallback: u32) -> u32 {
    answer
        .granted_time
        .or(answer.validity_time)
        .filter(|v| *v > 0)
        .unwrap_or(fallback)
        .max(MIN_REAUTH_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::PeerConfig;

    fn ocs_peer_config() -> PeerConfig {
        PeerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            origin_host: "siphon.test".to_string(),
            origin_realm: "test".to_string(),
            destination_host: None,
            destination_realm: "test".to_string(),
            local_ip: "127.0.0.1".parse().unwrap(),
            application_ids: vec![(0, dictionary::RO_APP_ID)],
            watchdog_interval: 3600,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        }
    }

    /// A scriptable loopback mock OCS. Each inbound CCR is answered with a CCA
    /// carrying `result_code` (+ optional MSCC grant), echoing Session-Id and
    /// CC-Request-Type/Number. `grant_secs`/`fua` are put inside MSCC — the
    /// correct RFC 8506 codes — so this doubles as the known-answer oracle.
    async fn mock_ocs_manager(
        initial_result: u32,
        grant_secs: Option<u32>,
        update_result: u32,
        fua: Option<u32>,
    ) -> (
        Arc<DiameterManager>,
        tokio::sync::mpsc::Receiver<crate::diameter::peer::IncomingRequest>,
        Arc<StdMutex<Vec<serde_json::Value>>>,
    ) {
        use crate::diameter::codec::{
            self, encode_avp_grouped, encode_avp_u32, encode_avp_utf8, encode_diameter_message,
            FLAG_REQUEST,
        };
        use crate::diameter::dictionary::avp;
        use crate::diameter::peer::spawn_connection_tasks;
        use crate::diameter::DiameterClient;
        use tokio::io::{AsyncWriteExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Every CCR the OCS receives, decoded, for wire-level assertions.
        let captured: Arc<StdMutex<Vec<serde_json::Value>>> = Arc::new(StdMutex::new(Vec::new()));
        let cap_task = Arc::clone(&captured);
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (read_half, mut write_half) = tokio::io::split(stream);
            let mut reader = BufReader::new(read_half);
            while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
                let Some(msg) = codec::decode_diameter(&bytes) else {
                    continue;
                };
                if !msg.is_request || msg.command_code != dictionary::CMD_CREDIT_CONTROL {
                    // Answer anything else (a stray DWR) by clearing the R-bit.
                    let mut answer = bytes;
                    if answer.len() > 4 {
                        answer[4] &= !FLAG_REQUEST;
                    }
                    let _ = write_half.write_all(&answer).await;
                    continue;
                }
                if let Ok(mut guard) = cap_task.lock() {
                    guard.push(msg.avps.clone());
                }
                let req_type = msg.avps.get("CC-Request-Type").and_then(|v| v.as_u64()).unwrap_or(0);
                // Answer per CC-Request-Type: UPDATE (2) gets update_result;
                // TERMINATION (3) is always acknowledged; INITIAL (1) / EVENT (4)
                // get initial_result. A grant is included only on success.
                let (result_code, include_grant) = match req_type {
                    2 => (update_result, update_result == 2001),
                    3 => (2001, false),
                    _ => (initial_result, initial_result == 2001),
                };
                let mut avps = Vec::new();
                if let Some(sid) = msg.avps.get("Session-Id").and_then(|v| v.as_str()) {
                    avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, sid));
                }
                avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
                avps.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_TYPE, req_type as u32));
                if let Some(rn) = msg.avps.get("CC-Request-Number").and_then(|v| v.as_u64()) {
                    avps.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_NUMBER, rn as u32));
                }
                // MSCC grant (correct RFC 8506 codes) — only on a successful answer.
                if include_grant && (grant_secs.is_some() || fua.is_some()) {
                    let mut mscc = Vec::new();
                    if let Some(secs) = grant_secs {
                        let gsu = encode_avp_u32(avp::CC_TIME, secs);
                        mscc.extend_from_slice(&encode_avp_grouped(avp::GRANTED_SERVICE_UNIT, &gsu));
                    }
                    if let Some(action) = fua {
                        let fui = encode_avp_u32(avp::FINAL_UNIT_ACTION, action);
                        mscc.extend_from_slice(&encode_avp_grouped(
                            avp::FINAL_UNIT_INDICATION,
                            &fui,
                        ));
                    }
                    avps.extend_from_slice(&encode_avp_grouped(
                        avp::MULTIPLE_SERVICES_CREDIT_CONTROL,
                        &mscc,
                    ));
                }
                let cca = encode_diameter_message(
                    0,
                    dictionary::CMD_CREDIT_CONTROL,
                    dictionary::RO_APP_ID,
                    msg.hop_by_hop,
                    msg.end_to_end,
                    &avps,
                );
                if write_half.write_all(&cca).await.is_err() {
                    break;
                }
            }
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(16);
        let peer = spawn_connection_tasks(ocs_peer_config(), client_stream, incoming_tx);
        let manager = Arc::new(DiameterManager::new());
        manager.register("ocs".to_string(), Arc::new(DiameterClient::new(peer)));
        (manager, incoming_rx, captured)
    }

    fn enabled_config() -> RoConfig {
        RoConfig {
            enabled: true,
            // Long fallback so no re-auth fires during the fast leak test.
            reauth_interval_secs: 3600,
            requested_seconds: 30,
            rating_group: Some(100),
            ..Default::default()
        }
    }

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
        let (manager, _rx, _cap) =
            mock_ocs_manager(2001, Some(MIN_REAUTH_SECS), DIAMETER_CREDIT_LIMIT_REACHED, None).await;
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
        assert_eq!(service.active_session_count(), 0, "denied session must drain");
        assert_eq!(
            torn_down.load(Ordering::Relaxed),
            1,
            "teardown hook must fire exactly once"
        );
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
        let ids: std::collections::HashSet<_> =
            sessions.iter().map(|s| s.session_id().to_string()).collect();
        assert_eq!(ids.len(), 40, "session-ids must be unique across concurrent calls");
        let wire_ids: std::collections::HashSet<_> = captured
            .lock()
            .unwrap()
            .iter()
            .filter_map(|c| c.get("Session-Id").and_then(|v| v.as_str()).map(String::from))
            .collect();
        assert_eq!(wire_ids.len(), 40, "on-the-wire CCR Session-Ids must be unique too");

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
            assert!(seen.insert(session.session_id().to_string()), "Session-Id reused at cycle {i}");
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

    /// Pull the IMS-Information block out of a captured CCR, if it carries one.
    fn ims_information(ccr: &serde_json::Value) -> Option<&serde_json::Value> {
        ccr.get("Service-Information")?.get("IMS-Information")
    }

    fn ccr_of_type(ccrs: &[serde_json::Value], request_type: u64) -> serde_json::Value {
        ccrs.iter()
            .find(|c| c.get("CC-Request-Type").and_then(|v| v.as_u64()) == Some(request_type))
            .unwrap_or_else(|| panic!("no CCR of type {request_type} was sent"))
            .clone()
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
            ims_information(&initial).and_then(|i| i.get("Trunk-Group-Id")).is_none(),
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
        assert_eq!(busy, Some(-486));
        assert_eq!(no_answer, Some(-408));
        assert_eq!(exhausted, Some(-402));

        let all = [normal, busy, no_answer, exhausted];
        let distinct: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(distinct.len(), all.len(), "all four must be distinguishable");
    }

    #[tokio::test]
    async fn a_terminate_with_no_cause_omits_the_avp() {
        // `None` means "no cause to report" and must not be encoded as a 0 that
        // claims the call ended normally.
        assert_eq!(cause_code_on_the_wire(None).await, None);
    }
}
