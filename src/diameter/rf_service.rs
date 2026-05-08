//! Runtime helper that bridges siphon's lifecycle hooks (registrar
//! on-change, B2BUA `CallEvent`, proxy `Forward2xx` / in-dialog BYE) to
//! the Rf protocol layer in [`super::rf`].
//!
//! Why a separate type instead of calling `rf::send_acr_*` from each
//! call site:
//!
//! - Centralizes peer resolution (`rf.peer` config → explicit name →
//!   first registered peer) so all three auto-emit paths route the same
//!   way.
//! - Enforces the TS 32.299 §6.5 non-blocking guarantee — every send is
//!   wrapped in a tokio task so a slow CDF cannot stall the SIP path.
//! - Holds the per-session record-number counter (atomic `AtomicU32`)
//!   that ACR-INTERIM and ACR-STOP need to satisfy RFC 6733 §9.8.3.
//! - Spawns and tracks the per-session INTERIM timer when the CDF
//!   negotiates an `Acct-Interim-Interval` in ACA-START.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::RfConfig;
use crate::diameter::peer::DiameterPeer;
use crate::diameter::rf::{
    self, termination_cause, AccountingAnswer, AccountingParams, AccountingRecordType,
};
use crate::diameter::ro::{ImsChargingData, NodeFunctionality, NodeRole};
use crate::diameter::DiameterManager;

/// State held per active accounting session.
///
/// Cloneable handle (the inner state is held behind `Arc`s) so the same
/// session can be referenced from the proxy session map, the INTERIM
/// timer task, and the STOP path simultaneously.
#[derive(Clone)]
pub struct RfChargingSession {
    inner: Arc<RfSessionInner>,
}

struct RfSessionInner {
    /// Diameter Session-Id returned by the CDF in ACA-START.
    session_id: String,
    /// Monotonic Record-Number counter per RFC 6733 §9.8.3 — START uses
    /// 0, INTERIM increments to 1..N, STOP uses N+1.  Reads via
    /// `next_record_number()` to enforce monotonicity across threads.
    record_number: AtomicU32,
    /// Whether STOP has already been sent.  Idempotent termination so
    /// the proxy + a manual `cdr.write()` cannot double-emit.
    stopped: AtomicU32,
    /// Negotiated INTERIM cadence (seconds).  Zero = disabled.
    interim_interval_secs: u32,
    /// Handle for the spawned INTERIM timer task.  Aborted on STOP.
    interim_handle: Mutex<Option<JoinHandle<()>>>,
    /// Result-Code from the last completed ACR exchange (most operators
    /// want the START code stamped on the CDR; STOP overrides if it
    /// arrives before the CDR is written).
    last_result_code: AtomicU32,
}

impl RfChargingSession {
    pub fn session_id(&self) -> &str {
        &self.inner.session_id
    }

    pub fn last_result_code(&self) -> Option<u32> {
        let raw = self.inner.last_result_code.load(Ordering::Relaxed);
        if raw == 0 {
            None
        } else {
            Some(raw)
        }
    }

    pub fn interim_interval(&self) -> u32 {
        self.inner.interim_interval_secs
    }

    fn next_record_number(&self) -> u32 {
        self.inner.record_number.fetch_add(1, Ordering::Relaxed)
    }
}

/// Bridges siphon's lifecycle hooks to [`crate::diameter::rf::send_acr`].
pub struct RfChargingService {
    manager: Arc<DiameterManager>,
    config: RfConfig,
    /// Cached `NodeFunctionality` parsed from `config.node_functionality`
    /// at construction time so every emit path doesn't pay the parse
    /// cost on the hot path.
    node_functionality: Option<NodeFunctionality>,
}

impl RfChargingService {
    pub fn new(manager: Arc<DiameterManager>, config: RfConfig) -> Arc<Self> {
        let node_functionality = NodeFunctionality::from_str_ci(&config.node_functionality);
        if node_functionality.is_none() {
            warn!(
                node_functionality = %config.node_functionality,
                "rf: unrecognized node_functionality, will be omitted from ACRs"
            );
        }
        Arc::new(Self {
            manager,
            config,
            node_functionality,
        })
    }

    pub fn config(&self) -> &RfConfig {
        &self.config
    }

    pub fn node_functionality(&self) -> Option<NodeFunctionality> {
        self.node_functionality
    }

    pub fn auto_emit_proxy(&self) -> bool {
        self.config.enabled && self.config.auto_emit_proxy
    }

    pub fn auto_emit_b2bua(&self) -> bool {
        self.config.enabled && self.config.auto_emit_b2bua
    }

    pub fn auto_emit_register(&self) -> bool {
        self.config.enabled && self.config.auto_emit_register
    }

    /// Resolve the CDF peer to send the next ACR on.  Configured peer
    /// name takes precedence; falls back to the first registered peer
    /// (matching the existing pattern used by Cx/Sh/Rx).
    fn pick_peer(&self) -> Option<Arc<DiameterPeer>> {
        if let Some(name) = self.config.peer.as_deref() {
            if let Some(client) = self.manager.client(name) {
                return Some(client.peer().clone());
            }
            warn!(
                peer = %name,
                "rf: configured peer not connected, falling back to any peer"
            );
        }
        self.manager.any_client().map(|c| c.peer().clone())
    }

    fn baseline_ims(&self) -> ImsChargingData {
        ImsChargingData {
            node_functionality: self.node_functionality,
            ..Default::default()
        }
    }

    /// Send ACR-START.  Returns a session handle that the caller stores
    /// alongside the call/dialog so subsequent INTERIM and STOP requests
    /// can use the same Session-Id and record-number sequence.  Returns
    /// `None` if no Diameter peer is connected, or if the CDF rejects
    /// the START — auto-emit is best-effort per TS 32.299 §6.5.
    pub async fn acr_start(
        self: &Arc<Self>,
        ims_data: ImsChargingData,
        user_name: Option<String>,
    ) -> Option<RfChargingSession> {
        if !self.config.enabled {
            return None;
        }
        let peer = self.pick_peer()?;
        let mut params = AccountingParams::new(AccountingRecordType::StartRecord);
        params.user_name = user_name.as_deref();
        params.ims_data = Some(&ims_data);
        params.event_timestamp = Some(SystemTime::now());
        params.service_context_id = Some(self.config.service_context_id.as_str());

        let answer = match rf::send_acr(&peer, &params).await {
            Ok(a) => a,
            Err(error) => {
                warn!(error = %error, "rf: ACR-START failed");
                return None;
            }
        };

        let session_id = answer.session_id.clone()?;
        let interim = answer
            .interim_interval
            .filter(|v| *v > 0)
            .unwrap_or(self.config.interim_interval_secs);
        let session = RfChargingSession {
            inner: Arc::new(RfSessionInner {
                session_id: session_id.clone(),
                record_number: AtomicU32::new(1),
                stopped: AtomicU32::new(0),
                interim_interval_secs: interim,
                interim_handle: Mutex::new(None),
                last_result_code: AtomicU32::new(answer.result_code),
            }),
        };

        if interim > 0 {
            self.spawn_interim_timer(&session, ims_data.clone(), user_name.clone())
                .await;
        }
        info!(
            session_id = %session_id,
            result_code = answer.result_code,
            interim_secs = interim,
            "rf: ACR-START sent"
        );
        Some(session)
    }

    /// Send a one-shot ACR-EVENT (REGISTER, MESSAGE, SUBSCRIBE, …).
    /// Result is the parsed answer so callers can record it on a CDR.
    pub async fn acr_event(
        &self,
        ims_data: ImsChargingData,
        user_name: Option<String>,
    ) -> Option<AccountingAnswer> {
        if !self.config.enabled {
            return None;
        }
        let peer = self.pick_peer()?;
        let mut params = AccountingParams::new(AccountingRecordType::EventRecord);
        params.user_name = user_name.as_deref();
        params.ims_data = Some(&ims_data);
        params.event_timestamp = Some(SystemTime::now());
        params.service_context_id = Some(self.config.service_context_id.as_str());

        match rf::send_acr(&peer, &params).await {
            Ok(answer) => {
                debug!(
                    result_code = answer.result_code,
                    "rf: ACR-EVENT sent"
                );
                Some(answer)
            }
            Err(error) => {
                warn!(error = %error, "rf: ACR-EVENT failed");
                None
            }
        }
    }

    /// Send ACR-INTERIM for an active session.  Caller-driven; the
    /// per-session timer task uses this internally.  Skipped if the
    /// session has already been STOPped.
    pub async fn acr_interim(
        &self,
        session: &RfChargingSession,
        mut ims_data: ImsChargingData,
        user_name: Option<String>,
    ) -> Option<AccountingAnswer> {
        if !self.config.enabled {
            return None;
        }
        if session.inner.stopped.load(Ordering::Relaxed) != 0 {
            return None;
        }
        let peer = self.pick_peer()?;
        // Ensure node_functionality is populated even if the caller
        // didn't supply it (e.g. the timer task only carries the
        // baseline IMS data).
        if ims_data.node_functionality.is_none() {
            ims_data.node_functionality = self.node_functionality;
        }
        let record_number = session.next_record_number();
        let mut params = AccountingParams::new(AccountingRecordType::InterimRecord);
        params.session_id = Some(&session.inner.session_id);
        params.record_number = record_number;
        params.user_name = user_name.as_deref();
        params.ims_data = Some(&ims_data);
        params.event_timestamp = Some(SystemTime::now());
        params.service_context_id = Some(self.config.service_context_id.as_str());

        match rf::send_acr(&peer, &params).await {
            Ok(answer) => {
                session
                    .inner
                    .last_result_code
                    .store(answer.result_code, Ordering::Relaxed);
                debug!(
                    session_id = %session.inner.session_id,
                    record_number,
                    result_code = answer.result_code,
                    "rf: ACR-INTERIM sent"
                );
                Some(answer)
            }
            Err(error) => {
                warn!(
                    session_id = %session.inner.session_id,
                    error = %error,
                    "rf: ACR-INTERIM failed"
                );
                None
            }
        }
    }

    /// Send ACR-STOP and tear down any INTERIM timer.  Idempotent —
    /// repeated calls after the first are no-ops.
    pub async fn acr_stop(
        &self,
        session: &RfChargingSession,
        mut ims_data: ImsChargingData,
        user_name: Option<String>,
        termination_cause_value: u32,
    ) -> Option<AccountingAnswer> {
        if !self.config.enabled {
            return None;
        }
        // Atomic flip of the stopped flag — only the first caller proceeds.
        if session
            .inner
            .stopped
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        if let Some(handle) = session.inner.interim_handle.lock().await.take() {
            handle.abort();
        }

        let peer = self.pick_peer()?;
        if ims_data.node_functionality.is_none() {
            ims_data.node_functionality = self.node_functionality;
        }
        let record_number = session.next_record_number();
        let mut params = AccountingParams::new(AccountingRecordType::StopRecord);
        params.session_id = Some(&session.inner.session_id);
        params.record_number = record_number;
        params.termination_cause = Some(termination_cause_value);
        params.user_name = user_name.as_deref();
        params.ims_data = Some(&ims_data);
        params.event_timestamp = Some(SystemTime::now());
        params.service_context_id = Some(self.config.service_context_id.as_str());

        match rf::send_acr(&peer, &params).await {
            Ok(answer) => {
                session
                    .inner
                    .last_result_code
                    .store(answer.result_code, Ordering::Relaxed);
                info!(
                    session_id = %session.inner.session_id,
                    record_number,
                    result_code = answer.result_code,
                    termination_cause = termination_cause_value,
                    "rf: ACR-STOP sent"
                );
                Some(answer)
            }
            Err(error) => {
                warn!(
                    session_id = %session.inner.session_id,
                    error = %error,
                    "rf: ACR-STOP failed"
                );
                None
            }
        }
    }

    async fn spawn_interim_timer(
        self: &Arc<Self>,
        session: &RfChargingSession,
        ims_data: ImsChargingData,
        user_name: Option<String>,
    ) {
        let interval = std::time::Duration::from_secs(session.inner.interim_interval_secs as u64);
        let service = Arc::clone(self);
        let task_session = session.clone();
        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick (which `tokio::time::interval`
            // emits as soon as the future is polled).
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if task_session.inner.stopped.load(Ordering::Relaxed) != 0 {
                    break;
                }
                let _ = service
                    .acr_interim(&task_session, ims_data.clone(), user_name.clone())
                    .await;
            }
        });
        *session.inner.interim_handle.lock().await = Some(handle);
    }
}

/// Convenience: derive the [`Termination-Cause`](termination_cause)
/// value from a SIP teardown reason string ("bye" / "session_timer" /
/// "admin" / "error").  Falls back to `DIAMETER_LOGOUT(1)`.
pub fn termination_cause_for_reason(reason: &str) -> u32 {
    match reason {
        "session_timer" | "session_timeout" => termination_cause::DIAMETER_SESSION_TIMEOUT,
        "admin" | "administrative" | "shutdown" => termination_cause::DIAMETER_ADMINISTRATIVE,
        "error" | "transport" => termination_cause::DIAMETER_LINK_BROKEN,
        _ => termination_cause::DIAMETER_LOGOUT,
    }
}

/// Build an [`ImsChargingData`] from a SIP request, populating every
/// IMS-Information sub-AVP that can be derived from the headers.
///
/// Role-of-Node determination follows TS 24.229 §5.4.3.2 / RFC 5502:
/// 1. `P-Served-User` `sescase=orig` → ORIGINATING_ROLE,
///    `sescase=term` → TERMINATING_ROLE.
/// 2. Fallback: caller supplies an `is_local_uri` predicate so the proxy
///    can decide based on whether the From / P-Asserted-Identity is a
///    locally-served identity.  When `None`, defaults to ORIGINATING_ROLE.
///
/// `node_functionality` comes from `RfConfig.node_functionality` so the
/// caller can configure once per deployment role (S-CSCF / P-CSCF / AS).
pub fn ims_data_from_request<F>(
    message: &crate::sip::SipMessage,
    node_functionality: Option<NodeFunctionality>,
    is_local_uri: F,
) -> ImsChargingData
where
    F: Fn(&str) -> bool,
{
    use crate::sip::headers::charging::{ChargingVector, ServedUser};

    let calling_party = message
        .headers
        .get("P-Asserted-Identity")
        .map(|s| strip_uri_brackets(s).to_string())
        .or_else(|| message.headers.get("From").map(|s| extract_uri(s).to_string()));
    let called_party = message
        .headers
        .get("To")
        .map(|s| extract_uri(s).to_string());
    let user_session_id = message.headers.get("Call-ID").cloned();

    let charging_vector = message
        .headers
        .get("P-Charging-Vector")
        .map(|v| ChargingVector::parse(v))
        .unwrap_or_default();
    let visited_network_id = message
        .headers
        .get("P-Visited-Network-ID")
        .and_then(|v| crate::sip::headers::charging::parse_visited_network_id(v));

    // Role determination: P-Served-User wins, else compare From-URI to
    // local-domain predicate, else default ORIGINATING_ROLE.
    let role_of_node = message
        .headers
        .get("P-Served-User")
        .and_then(|v| ServedUser::parse(v))
        .and_then(|su| match su.sescase.as_deref() {
            Some("orig") => Some(NodeRole::OriginatingRole),
            Some("term") => Some(NodeRole::TerminatingRole),
            _ => None,
        })
        .or_else(|| {
            let from_uri = message
                .headers
                .get("From")
                .map(|s| extract_uri(s).to_string());
            from_uri.as_deref().map(|uri| {
                if is_local_uri(uri) {
                    NodeRole::OriginatingRole
                } else {
                    NodeRole::TerminatingRole
                }
            })
        })
        .or(Some(NodeRole::OriginatingRole));

    let sip_method = message.method().map(|m| m.as_str().to_string());

    ImsChargingData {
        calling_party,
        called_party,
        sip_method,
        event: None,
        role_of_node,
        node_functionality,
        ims_charging_identifier: charging_vector.icid,
        cause_code: None,
        user_session_id,
        request_timestamp: Some(SystemTime::now()),
        response_timestamp: None,
        originating_ioi: charging_vector.orig_ioi,
        terminating_ioi: charging_vector.term_ioi,
        application_server: None,
        visited_network_id,
    }
}

fn strip_uri_brackets(s: &str) -> &str {
    let trimmed = s.trim();
    if let (Some(open), Some(close)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if open < close {
            return trimmed[open + 1..close].trim();
        }
    }
    trimmed
}

fn extract_uri(name_addr: &str) -> &str {
    strip_uri_brackets(name_addr.split(';').next().unwrap_or(name_addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn termination_cause_for_reason_default() {
        assert_eq!(termination_cause_for_reason("bye"), 1);
        assert_eq!(termination_cause_for_reason(""), 1);
    }

    #[test]
    fn termination_cause_for_reason_session_timer() {
        assert_eq!(termination_cause_for_reason("session_timer"), 8);
        assert_eq!(termination_cause_for_reason("session_timeout"), 8);
    }

    #[test]
    fn termination_cause_for_reason_admin() {
        assert_eq!(termination_cause_for_reason("admin"), 4);
        assert_eq!(termination_cause_for_reason("shutdown"), 4);
    }

    #[test]
    fn termination_cause_for_reason_link_broken() {
        assert_eq!(termination_cause_for_reason("error"), 5);
        assert_eq!(termination_cause_for_reason("transport"), 5);
    }

    #[test]
    fn service_disabled_when_config_disabled() {
        let manager = Arc::new(DiameterManager::new());
        let mut cfg = RfConfig::default();
        cfg.enabled = false;
        let service = RfChargingService::new(manager, cfg);
        assert!(!service.auto_emit_proxy());
        assert!(!service.auto_emit_b2bua());
        assert!(!service.auto_emit_register());
    }

    #[test]
    fn service_emits_when_enabled() {
        let manager = Arc::new(DiameterManager::new());
        let mut cfg = RfConfig::default();
        cfg.enabled = true;
        let service = RfChargingService::new(manager, cfg);
        assert!(service.auto_emit_proxy());
        assert!(service.auto_emit_b2bua());
        assert!(service.auto_emit_register());
    }

    #[test]
    fn service_resolves_node_functionality() {
        let manager = Arc::new(DiameterManager::new());
        let mut cfg = RfConfig::default();
        cfg.enabled = true;
        cfg.node_functionality = "scscf".into();
        let service = RfChargingService::new(manager, cfg);
        assert_eq!(service.node_functionality(), Some(NodeFunctionality::SCscf));
    }

    #[test]
    fn service_unknown_node_functionality_logs_and_returns_none() {
        let manager = Arc::new(DiameterManager::new());
        let mut cfg = RfConfig::default();
        cfg.enabled = true;
        cfg.node_functionality = "totally-bogus".into();
        let service = RfChargingService::new(manager, cfg);
        assert_eq!(service.node_functionality(), None);
    }

    // ── ims_data_from_request ───────────────────────────────────────────

    fn parse_test_sip(raw: &str) -> crate::sip::SipMessage {
        crate::sip::parser::parse_sip_message_bytes(raw.as_bytes())
            .expect("test SIP message must parse")
    }

    #[test]
    fn ims_data_extracts_charging_vector_icid_and_iois() {
        let raw = concat!(
            "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc.atlanta.example.com;branch=z9hG4bK776\r\n",
            "From: <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
            "To: <sip:bob@biloxi.example.com>\r\n",
            "Call-ID: a84b4c76e66710\r\n",
            "CSeq: 1 INVITE\r\n",
            "P-Charging-Vector: icid-value=icid-test-001;orig-ioi=home1.net;term-ioi=home2.net\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let msg = parse_test_sip(raw);
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::SCscf), |_| false);

        assert_eq!(ims.ims_charging_identifier.as_deref(), Some("icid-test-001"));
        assert_eq!(ims.originating_ioi.as_deref(), Some("home1.net"));
        assert_eq!(ims.terminating_ioi.as_deref(), Some("home2.net"));
        assert_eq!(ims.user_session_id.as_deref(), Some("a84b4c76e66710"));
        assert_eq!(ims.sip_method.as_deref(), Some("INVITE"));
        assert_eq!(ims.node_functionality, Some(NodeFunctionality::SCscf));
    }

    #[test]
    fn ims_data_role_from_p_served_user() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host;branch=z9hG4bK1\r\n",
            "From: <sip:alice@example.com>;tag=a\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: c\r\n",
            "CSeq: 1 INVITE\r\n",
            "P-Served-User: <sip:bob@example.com>;sescase=term;regstate=reg\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let msg = parse_test_sip(raw);
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::SCscf), |_| false);
        assert_eq!(ims.role_of_node, Some(NodeRole::TerminatingRole));
    }

    #[test]
    fn ims_data_role_falls_back_to_local_predicate() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host;branch=z9hG4bK1\r\n",
            "From: <sip:alice@home.example.com>;tag=a\r\n",
            "To: <sip:bob@other.example.com>\r\n",
            "Call-ID: c\r\n",
            "CSeq: 1 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let msg = parse_test_sip(raw);
        // Predicate: "home.example.com" caller is local → originating role
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::SCscf), |uri| {
            uri.contains("home.example.com")
        });
        assert_eq!(ims.role_of_node, Some(NodeRole::OriginatingRole));

        // With opposite predicate → terminating
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::SCscf), |uri| {
            uri.contains("other.example.com")
        });
        assert_eq!(ims.role_of_node, Some(NodeRole::TerminatingRole));
    }

    #[test]
    fn ims_data_extracts_visited_network_id_for_roaming() {
        let raw = concat!(
            "REGISTER sip:home.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host;branch=z9hG4bK1\r\n",
            "From: <sip:alice@home.example.com>;tag=a\r\n",
            "To: <sip:alice@home.example.com>\r\n",
            "Call-ID: c\r\n",
            "CSeq: 1 REGISTER\r\n",
            "P-Visited-Network-ID: visited.example.com\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let msg = parse_test_sip(raw);
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::PCscf), |_| true);
        assert_eq!(ims.visited_network_id.as_deref(), Some("visited.example.com"));
    }

    #[test]
    fn ims_data_strips_uri_brackets_and_params() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host;branch=z9hG4bK1\r\n",
            "From: \"Alice\" <sip:alice@example.com>;tag=a\r\n",
            "To: \"Bob\" <sip:bob@example.com>\r\n",
            "Call-ID: c\r\n",
            "CSeq: 1 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let msg = parse_test_sip(raw);
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::SCscf), |_| false);
        assert_eq!(ims.calling_party.as_deref(), Some("sip:alice@example.com"));
        assert_eq!(ims.called_party.as_deref(), Some("sip:bob@example.com"));
    }

    #[test]
    fn ims_data_uses_p_asserted_identity_when_present() {
        let raw = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host;branch=z9hG4bK1\r\n",
            "From: <sip:anonymous@anonymous.invalid>;tag=a\r\n",
            "To: <sip:bob@example.com>\r\n",
            "P-Asserted-Identity: <sip:alice@home.example.com>\r\n",
            "Call-ID: c\r\n",
            "CSeq: 1 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let msg = parse_test_sip(raw);
        let ims = ims_data_from_request(&msg, Some(NodeFunctionality::SCscf), |_| false);
        assert_eq!(
            ims.calling_party.as_deref(),
            Some("sip:alice@home.example.com"),
            "P-Asserted-Identity should override From for Calling-Party-Address"
        );
    }
}
