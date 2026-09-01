//! Lawful interception: ETSI X1 provisioning, X2 IRI delivery, X3 content.
//!
//! # Where interception is decided
//!
//! The dispatcher calls [`LiManager::check_session`] on every SIP message, on
//! every call leg, on every path. A warrant that matches is acted on whether or
//! not the operator's Python script cooperates.
//!
//! It is asked of the *session* rather than of the message. Deciding each
//! message on its own identities assumes every message of a dialog carries the
//! target in matchable form, and they do not — a re-INVITE from the far end
//! swaps From and To, an in-dialog REFER or NOTIFY carries whoever sent it, a
//! BYE can come from either side. That assumption is how a warrant delivers the
//! INVITE and then misses the teardown.
//!
//! This is a change from the previous behaviour and the reason for it is worth
//! stating plainly: interception used to be opt-in from Python — the only
//! callers of the matching code were the `li.*` script API — so a script that
//! omitted a call on one path silently intercepted nothing there. For a
//! warranted intercept a missed leg is a reportable failure, and it must not
//! depend on the operator's code being right. The `li.*` script API remains,
//! for visibility and for operator-driven recording that is not a warrant, but
//! it is no longer the gate.
//!
//! # Identifiers on the handover interfaces
//!
//! Clause 6 of TS 103 221-2 requires that X2 and X3 records for one session
//! carry the same Correlation ID, and every PDU carries the task's XID. Because
//! X3 is emitted by the media engine and X2 by this process, that is an
//! invariant spanning two binaries — [`IriEvent`] therefore carries both
//! values explicitly rather than letting each side derive its own.

pub mod asn1;
pub mod pdu;
pub mod siprec;
pub mod target;
pub mod x1;
pub mod x2;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::SystemTime;

use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::{LawfulInterceptConfig, MediaBackendKind};
use x1::store::{ContentCapability, DestinationStore, StoredTask, TaskMatch, TaskStore};
use x1::types::{DeliveryType, XId};

/// Where in a session an IRI record falls.
///
/// The begin/continue/end/report shape is TS 102 232-5 §5's, and it survives
/// here because it is what a mediation function reconstructs a session from —
/// but it is not on the X2 wire. An X2 PDU has no event-type field
/// (TS 103 221-2 clause 5.2); the MDF derives it from the SIP the record
/// carries. This decides what siphon does locally: where content capture starts
/// and stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IriEventType {
    /// Session/call initiation (INVITE received).
    Begin,
    /// Call progress (1xx provisional, re-INVITE).
    Continue,
    /// Session termination (BYE, CANCEL, error response).
    End,
    /// Standalone event (REGISTER, MESSAGE, SUBSCRIBE, etc.).
    Report,
}

/// An IRI (Intercept Related Information) event to be delivered via X2.
#[derive(Debug, Clone)]
pub struct IriEvent {
    /// The provisioned task this event belongs to.
    ///
    /// Its 16 bytes are the XID of every X2 and X3 PDU delivered for it.
    pub x_id: XId,
    /// The handover identifier the mediation function keys on.
    ///
    /// Taken from the task's `mediationDetails`; when the ADMF provisioned
    /// none, this is the XID's text form so the record is still attributable.
    pub liid: String,
    /// Correlation identifier for this session.
    ///
    /// Non-zero, stable for the life of the session, and identical to the value
    /// the media engine puts on the session's X3 PDUs.
    pub correlation_id: u64,
    /// The SIP Call-ID the correlation was derived from.
    pub call_id: String,
    /// Event type.
    pub event_type: IriEventType,
    /// Timestamp of the event.
    pub timestamp: SystemTime,
    /// SIP method (INVITE, BYE, REGISTER, etc.).
    pub sip_method: String,
    /// SIP status code (for responses), None for requests.
    pub status_code: Option<u16>,
    /// From URI.
    pub from_uri: String,
    /// To URI.
    pub to_uri: String,
    /// Request-URI (for requests).
    pub request_uri: Option<String>,
    /// Source IP of the SIP message.
    pub source_ip: Option<IpAddr>,
    /// Destination IP of the SIP message.
    pub destination_ip: Option<IpAddr>,
    /// What the task delivers.
    pub delivery_type: DeliveryType,
    /// Which end of the call the warrant names.
    ///
    /// Carried on the record because a mediation function renders a session
    /// relative to its target, and because the same value decides the
    /// target-relative direction on the session's X3 packets.
    pub party: crate::li::target::MatchedParty,
    /// Where this event goes: exactly the X2-capable destinations the task
    /// names in `listOfDIDs`, resolved at match time.
    pub destinations: Vec<SocketAddr>,
    /// Raw SIP message bytes (included in IRI for full signalling capture).
    pub raw_message: Option<Vec<u8>>,
}

/// Audit log entry — every X1 operation and intercept match is recorded.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// When it happened.
    pub timestamp: SystemTime,
    /// What happened.
    pub operation: AuditOperation,
    /// The task or destination it concerned, if any.
    pub subject: Option<String>,
    /// Free-text detail.
    pub detail: String,
}

/// The operations recorded in the compliance audit trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditOperation {
    /// An X1 provisioning operation, named by its message type.
    Provisioning(String),
    /// A message matched an active warrant.
    InterceptMatch,
    /// An IRI record was handed to the X2 delivery path.
    IriDelivered,
    /// Content capture started for a session.
    MediaCaptureStarted,
    /// Content capture stopped for a session.
    MediaCaptureStopped,
    /// The LI subsystem started.
    SystemStarted,
    /// The LI subsystem stopped.
    SystemStopped,
}

/// Derive the per-session Correlation ID from a SIP Call-ID.
///
/// TS 103 221-2 clause 6 requires a non-zero correlation that ties one
/// session's X2 and X3 records together. Deriving it deterministically from the
/// Call-ID means this process and the media engine reach the same value without
/// having to exchange it, and it stays stable across the whole dialog.
///
/// Used only when the ADMF did not provision a `correlationID`; when it did,
/// that value is honoured, because we do not always own that number.
pub fn correlation_from_call_id(call_id: &str) -> u64 {
    // FNV-1a: stable across processes and builds, unlike `DefaultHasher`,
    // which is explicitly not guaranteed to be. That stability is the whole
    // point — the media engine must derive the same value.
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for byte in call_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    // Zero is reserved for keepalive PDUs, so it must never be a session's
    // correlation.
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// A live X3 content interception on one call.
///
/// Kept so three later questions can be answered: which warrant a delivery
/// fault belongs to, which destination to report it against, and what to
/// detach when the call ends.
#[derive(Debug, Clone)]
pub struct ActiveIntercept {
    /// The task this interception services.
    pub x_id: XId,
    /// The destination the content is being delivered to.
    pub d_id: x1::types::DId,
    /// The leg the engine keys the interception on.
    pub from_tag: String,
    /// The session correlation, shared with this session's X2 records.
    pub correlation_id: u64,
}

/// The lawful-intercept subsystem.
#[derive(Clone)]
pub struct LiManager {
    tasks: TaskStore,
    destinations: DestinationStore,
    iri_sender: mpsc::Sender<IriEvent>,
    audit_sender: mpsc::Sender<AuditEntry>,
    config: Arc<LawfulInterceptConfig>,
    /// The ADMF client, when the network-element-to-ADMF direction is
    /// configured. Needed on the delivery path so a content-loss event can be
    /// reported rather than only logged.
    x1_client: Arc<std::sync::OnceLock<Arc<x1::client::X1Client>>>,
    /// Live X3 interceptions, keyed by SIP Call-ID.
    x3_attachments: Arc<DashMap<String, Vec<ActiveIntercept>>>,
    /// Per-session matching decisions, keyed by SIP Call-ID.
    ///
    /// See [`LiManager::check_session`].
    decisions: Arc<DashMap<String, SessionDecision>>,
}

/// What was decided about one session, and when.
#[derive(Debug, Clone)]
struct SessionDecision {
    /// The provisioning generation this was decided under. A decision taken
    /// before a warrant was activated says nothing about the traffic after it.
    generation: u64,
    /// The warrants that matched, by XID and the party each names. Empty means
    /// the session matched nothing, which is worth remembering too — it is the
    /// common case and the one that costs the most to re-derive.
    ///
    /// Deliberately not the [`TaskMatch`] itself: that embeds a whole
    /// `StoredTask`, so caching it would both duplicate the store and go stale
    /// the moment a `ModifyTask` changed a delivery type or a DID. The task is
    /// re-read by XID at delivery, which is one lookup and always current.
    matched: Vec<(XId, crate::li::target::MatchedParty)>,
    /// Message instances already recorded for this session.
    ///
    /// Interception runs before transaction matching, so a UDP retransmission
    /// arrives here as an ordinary message and would produce a second record
    /// of something the mediation function already has — up to seven times for
    /// one INVITE under RFC 3261's timers. Worse, it would re-run the
    /// session's lifecycle: a retransmitted INVITE would restart content
    /// capture on a call already being captured.
    ///
    /// Held per session so it is evicted with the session and needs no
    /// lifetime rule of its own. Hashes rather than the keys themselves,
    /// because the only question asked of it is "seen this before".
    seen: std::collections::HashSet<u64>,
}

/// How many message instances one session remembers having recorded.
///
/// A dialog is dozens of messages, not thousands; this is generous. Past it
/// de-duplication stops and every message is recorded, because for a warrant a
/// duplicated record is recoverable at the mediation function and a dropped one
/// is not. The degraded mode is therefore the old behaviour, never a gap.
const MAX_SEEN_PER_SESSION: usize = 512;

/// How many sessions may have a remembered decision.
///
/// A bound rather than a hope: the key is the Call-ID, which is chosen by
/// whoever sent the message. Without a cap, a flood of requests bearing
/// distinct Call-IDs would grow this map until the process died, which is a
/// remote memory-exhaustion vector on an interface that faces the network.
///
/// On overflow the map is cleared rather than evicted one entry at a time.
/// Clearing costs a re-derivation for the sessions that were in it, which is
/// exactly the behaviour before this cache existed — so the degraded mode is
/// the old correct one, never a missed interception.
const MAX_REMEMBERED_SESSIONS: usize = 100_000;

impl LiManager {
    /// Build the subsystem.
    ///
    /// `content_capability` states whether the configured media backend can
    /// deliver X3, which decides whether a content warrant may be provisioned
    /// at all.
    pub fn new(
        config: LawfulInterceptConfig,
        iri_channel_size: usize,
        content_capability: ContentCapability,
    ) -> (Self, mpsc::Receiver<IriEvent>, mpsc::Receiver<AuditEntry>) {
        let (iri_sender, iri_receiver) = mpsc::channel(iri_channel_size);
        let (audit_sender, audit_receiver) = mpsc::channel(10_000);

        let destinations = DestinationStore::new();
        let tasks = TaskStore::new(destinations.clone(), content_capability);

        let manager = Self {
            tasks,
            destinations,
            iri_sender,
            audit_sender,
            config: Arc::new(config),
            x1_client: Arc::new(std::sync::OnceLock::new()),
            x3_attachments: Arc::new(DashMap::new()),
            decisions: Arc::new(DashMap::new()),
        };

        let _ = manager.audit_sender.try_send(AuditEntry {
            timestamp: SystemTime::now(),
            operation: AuditOperation::SystemStarted,
            subject: None,
            detail: "LI subsystem initialized".to_string(),
        });

        info!("lawful intercept subsystem initialized");

        (manager, iri_receiver, audit_receiver)
    }

    /// Whether this node can deliver X3 content.
    ///
    /// Two independent conditions, both of which must hold:
    ///
    /// 1. `media.backend` must be the native engine — TS 103 221-2 framing is
    ///    implemented there and nowhere else.
    /// 2. The engine control contract must actually expose an attach verb.
    ///    Until it does there is nothing to send, so a content warrant is
    ///    refused rather than accepted and silently delivering nothing.
    pub fn content_capability_for(backend: MediaBackendKind) -> ContentCapability {
        match backend {
            MediaBackendKind::SiphonRtp => {
                if crate::li::x1::store::engine_supports_content() {
                    ContentCapability::Available
                } else {
                    ContentCapability::EngineContractLacksVerb
                }
            }
            other => ContentCapability::WrongBackend {
                backend: other.as_str(),
            },
        }
    }

    /// Every provisioned task whose warrant matches this message.
    ///
    /// Called by the dispatcher for every SIP message. When LI is disabled this
    /// is a single boolean test, so the cost on a node with no warrants is a
    /// predictable branch.
    pub fn check_message(
        &self,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> Vec<TaskMatch> {
        if !self.config.enabled {
            return Vec::new();
        }
        // A node with no warrants provisioned should not pay for the lookup.
        if self.tasks.is_empty() {
            return Vec::new();
        }
        self.tasks
            .match_message(request_uri, from_uri, to_uri, source_ip)
    }

    /// The warrants covering one session, deciding once per session rather than
    /// once per message.
    ///
    /// Two reasons, and the second is the important one.
    ///
    /// **It is cheaper.** Matching normalises the URIs and walks the index for
    /// every warrant, and this runs on every message on every leg. A dialog is
    /// dozens of messages about one pair of identities, so deciding it once and
    /// remembering the answer turns all but the first into a map lookup.
    ///
    /// **It is more correct.** Matching each message on its own identities
    /// quietly assumes every message of a session carries the target in a
    /// matchable form, and they do not: a re-INVITE from the far end swaps From
    /// and To, an in-dialog REFER or NOTIFY carries the identities of whoever
    /// sent it, and a BYE can come from either side. Deciding per message is
    /// how a warrant delivers the INVITE and then silently misses the BYE.
    /// Once a session is warranted, everything in it is intercepted.
    ///
    /// A remembered decision is only used while the provisioning generation has
    /// not moved: an `ActivateTask` must take effect on calls already in
    /// progress, so a session decided as unwarranted before it arrived is
    /// decided again after.
    pub fn check_session(
        &self,
        call_id: &str,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> Vec<TaskMatch> {
        if !self.config.enabled || self.tasks.is_empty() {
            return Vec::new();
        }

        let generation = self.tasks.generation();
        if let Some(decision) = self.decisions.get(call_id) {
            if decision.generation == generation {
                if decision.matched.is_empty() {
                    return Vec::new();
                }
                // Re-read each task rather than trusting a cached copy, so a
                // ModifyTask that changed a delivery type or a destination is
                // honoured on the very next message.
                return decision
                    .matched
                    .iter()
                    .filter_map(|(x_id, party)| {
                        self.tasks.get(*x_id).map(|task| TaskMatch {
                            task,
                            party: *party,
                        })
                    })
                    .collect();
            }
        }

        let matches = self
            .tasks
            .match_message(request_uri, from_uri, to_uri, source_ip);

        // Bounded, because the key is attacker-supplied. Clearing on overflow
        // costs a re-derivation, never a missed interception.
        if self.decisions.len() >= MAX_REMEMBERED_SESSIONS {
            warn!(
                remembered = self.decisions.len(),
                "LI session decisions hit the cap and were cleared; matching \
                 falls back to per-message until they repopulate"
            );
            self.decisions.clear();
        }
        self.decisions.insert(
            call_id.to_string(),
            SessionDecision {
                generation,
                matched: matches
                    .iter()
                    .map(|matched| (matched.task.details.x_id, matched.party))
                    .collect(),
                seen: std::collections::HashSet::new(),
            },
        );

        matches
    }

    /// Record that a message instance has been intercepted, once.
    ///
    /// Returns `false` when this exact instance has already been recorded for
    /// the session — a retransmission — and the caller should do nothing
    /// further with it.
    ///
    /// Interception is deliberately placed before transaction matching, so that
    /// a script cannot drop a message before it is intercepted. The cost of
    /// that placement is that retransmissions arrive here looking like new
    /// messages: RFC 3261's timers resend an unanswered INVITE up to seven
    /// times, and each would otherwise produce its own IRI record and re-run
    /// the session's lifecycle, restarting content capture on a call already
    /// being captured.
    ///
    /// The key is the message instance, not its content: the top `Via` branch
    /// identifies the transaction (§8.1.1.7 requires a new branch for a new
    /// one), and the CSeq, method and status separate the messages within it.
    /// A re-INVITE, an ACK and a second provisional all key differently; only
    /// a genuine resend of the same thing collides.
    pub fn record_message_once(&self, call_id: &str, key: u64) -> bool {
        let Some(mut session) = self.decisions.get_mut(call_id) else {
            // No decision means nothing matched, so nothing is being recorded
            // and there is nothing to de-duplicate.
            return true;
        };
        if session.seen.len() >= MAX_SEEN_PER_SESSION {
            // Fail open. A duplicate record is recoverable at the mediation
            // function; a dropped one is not.
            return true;
        }
        session.seen.insert(key)
    }

    /// Forget a session's decision, once the dialog it described is over.
    ///
    /// The cap exists for traffic that never reaches this; ordinary calls are
    /// released here, as they end.
    pub fn forget_session(&self, call_id: &str) {
        self.decisions.remove(call_id);
    }

    /// How many sessions currently have a remembered decision.
    ///
    /// Exposed so the leak tests can assert this drains rather than grows.
    pub fn remembered_session_count(&self) -> usize {
        self.decisions.len()
    }

    /// The Correlation ID to use for a task on a given session.
    ///
    /// Honours a value the ADMF provisioned; otherwise derives a stable
    /// non-zero one from the Call-ID.
    pub fn correlation_for(&self, task: &StoredTask, call_id: &str) -> u64 {
        match task.details.correlation_id {
            // Zero is reserved on the wire, so a provisioned zero is treated as
            // "not provisioned" rather than emitted.
            Some(provisioned) if provisioned != 0 => provisioned,
            _ => correlation_from_call_id(call_id),
        }
    }

    /// The LIID a task's records carry.
    ///
    /// From `mediationDetails` when the ADMF provisioned one, else the XID's
    /// text form so a record is never unattributable.
    pub fn liid_for(task: &StoredTask) -> String {
        task.details
            .primary_liid()
            .map(|liid| liid.as_str().to_string())
            .unwrap_or_else(|| task.details.x_id.to_string())
    }

    /// Build the IRI event for a task matching a message.
    ///
    /// Resolves the task's X2-capable destinations at match time, so an event
    /// carries exactly the sinks the warrant named.
    #[allow(clippy::too_many_arguments)]
    pub fn build_iri_event(
        &self,
        matched: &TaskMatch,
        event_type: IriEventType,
        call_id: &str,
        sip_method: &str,
        status_code: Option<u16>,
        from_uri: &str,
        to_uri: &str,
        request_uri: Option<String>,
        source_ip: Option<IpAddr>,
        raw_message: Option<Vec<u8>>,
    ) -> IriEvent {
        let task = &matched.task;
        let destinations = self
            .tasks
            .destinations_for_interface(task.details.x_id, false)
            .into_iter()
            .filter_map(|destination| destination.details.delivery_address.socket_addr())
            .collect();

        IriEvent {
            x_id: task.details.x_id,
            liid: Self::liid_for(task),
            correlation_id: self.correlation_for(task, call_id),
            call_id: call_id.to_string(),
            event_type,
            timestamp: SystemTime::now(),
            sip_method: sip_method.to_string(),
            status_code,
            from_uri: from_uri.to_string(),
            to_uri: to_uri.to_string(),
            request_uri,
            source_ip,
            destination_ip: None,
            delivery_type: task.details.delivery_type,
            party: matched.party,
            destinations,
            raw_message,
        }
    }

    /// Hand an IRI record to the X2 delivery path.
    pub fn emit_iri(&self, event: IriEvent) {
        if let Err(error) = self.iri_sender.try_send(event) {
            match error {
                mpsc::error::TrySendError::Full(event) => {
                    warn!(
                        xid = %event.x_id,
                        "X2 IRI channel full, dropping event — this is a compliance failure"
                    );
                }
                mpsc::error::TrySendError::Closed(event) => {
                    error!(xid = %event.x_id, "X2 IRI channel closed");
                }
            }
        }
    }

    /// Record an entry in the compliance audit trail.
    pub fn audit(&self, operation: AuditOperation, subject: Option<&str>, detail: String) {
        let entry = AuditEntry {
            timestamp: SystemTime::now(),
            operation,
            subject: subject.map(String::from),
            detail,
        };
        if self.audit_sender.try_send(entry).is_err() {
            error!("audit log channel full or closed — compliance violation");
        }
    }

    /// The provisioned tasks.
    pub fn tasks(&self) -> &TaskStore {
        &self.tasks
    }

    /// The provisioned destinations.
    pub fn destinations(&self) -> &DestinationStore {
        &self.destinations
    }

    /// The LI configuration.
    pub fn config(&self) -> &LawfulInterceptConfig {
        &self.config
    }

    /// Whether LI is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Attach the ADMF client, so delivery faults can be reported upward.
    pub fn set_x1_client(&self, client: Arc<x1::client::X1Client>) {
        let _ = self.x1_client.set(client);
    }

    /// The ADMF client, if the outbound direction is configured.
    pub fn x1_client(&self) -> Option<Arc<x1::client::X1Client>> {
        self.x1_client.get().cloned()
    }

    /// Record that content delivery started for a call.
    pub fn record_x3_attachment(&self, call_id: &str, attachment: ActiveIntercept) {
        self.x3_attachments
            .entry(call_id.to_string())
            .or_default()
            .push(attachment);
    }

    /// Every live interception on a call.
    pub fn x3_attachments_for(&self, call_id: &str) -> Vec<ActiveIntercept> {
        self.x3_attachments
            .get(call_id)
            .map(|entry| entry.clone())
            .unwrap_or_default()
    }

    /// Drop and return a call's interceptions, at teardown.
    pub fn take_x3_attachments(&self, call_id: &str) -> Vec<ActiveIntercept> {
        self.x3_attachments
            .remove(call_id)
            .map(|(_, attachments)| attachments)
            .unwrap_or_default()
    }

    /// How many calls currently have content delivery attached.
    ///
    /// Used by the per-module leak guard: this must drain to zero as calls end,
    /// or the map grows for the life of the process.
    pub fn x3_attachment_count(&self) -> usize {
        self.x3_attachments.len()
    }

}

impl std::fmt::Debug for LiManager {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LiManager")
            .field("enabled", &self.config.enabled)
            .field("tasks", &self.tasks.len())
            .field("destinations", &self.destinations.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x1::message::{DestinationDetails, MediationDetails, TaskDetails};
    use x1::types::{
        DId, DeliveryAddress, IpAddressPort, Liid, MediationDeliveryType, Port, TargetIdentifier,
    };
    use std::net::Ipv4Addr;

    fn test_config() -> LawfulInterceptConfig {
        LawfulInterceptConfig {
            enabled: true,
            audit_log: None,
            x1: None,
            x2: None,
            x3: None,
            siprec: None,
        }
    }

    fn manager() -> (
        LiManager,
        mpsc::Receiver<IriEvent>,
        mpsc::Receiver<AuditEntry>,
    ) {
        LiManager::new(test_config(), 100, ContentCapability::Available)
    }

    fn provision(manager: &LiManager, delivery: DeliveryType, liid: Option<&str>) -> XId {
        let d_id = DId::generate();
        manager
            .destinations()
            .create(DestinationDetails {
                d_id,
                friendly_name: None,
                delivery_type: DeliveryType::X2AndX3,
                delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                    port: Port::Tcp(42069),
                }),
            })
            .expect("destination must provision");

        let x_id = XId::generate();
        manager
            .tasks()
            .activate(TaskDetails {
                x_id,
                target_identifiers: vec![TargetIdentifier::SipUri(
                    "sip:alice@example.com".to_string(),
                )],
                delivery_type: delivery,
                list_of_dids: vec![d_id],
                list_of_dsids: Vec::new(),
                list_of_mediation_details: liid
                    .map(|value| MediationDetails {
                        liid: Liid::parse(value).expect("valid LIID"),
                        delivery_type: MediationDeliveryType::Hi2AndHi3,
                        start_time: None,
                        end_time: None,
                        list_of_dids: Vec::new(),
                    })
                    .into_iter()
                    .collect(),
                correlation_id: None,
                implicit_deactivation_allowed: None,
                product_id: None,
                list_of_service_types: Vec::new(),
            })
            .expect("task must provision");
        x_id
    }

    // --- per-session decisions ---------------------------------------------

    /// The reason the decision is per session rather than per message.
    ///
    /// A BYE from the far end carries the target in To rather than From, and a
    /// re-INVITE from the callee swaps them outright. Deciding each message on
    /// its own identities is how a warrant delivers the INVITE and then misses
    /// the teardown; the session's decision covers everything in it.
    #[test]
    fn a_warranted_session_stays_warranted_when_the_identities_move() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        let opening = manager.check_session(
            "call-1@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );
        assert_eq!(opening.len(), 1, "the INVITE names the target in From");

        // The far end's BYE: neither header is where the target was, and the
        // Request-URI is now the target's contact rather than the AoR.
        let teardown = manager.check_session(
            "call-1@example.com",
            Some("sip:alice@10.0.0.9:5060"),
            Some("<sip:bob@example.com>;tag=b"),
            Some("<sip:alice@example.com>;tag=a"),
            None,
        );
        assert_eq!(
            teardown.len(),
            1,
            "the session is warranted, so its teardown is intercepted too"
        );

        // And a message whose identities match nothing at all, on the same
        // session, is still covered.
        let opaque = manager.check_session(
            "call-1@example.com",
            Some("sip:anonymous@anonymous.invalid"),
            Some("<sip:anonymous@anonymous.invalid>;tag=x"),
            Some("<sip:anonymous@anonymous.invalid>"),
            None,
        );
        assert_eq!(opaque.len(), 1);
    }

    /// A warrant provisioned during a live call has to bite on that call.
    ///
    /// This is what the generation counter is for: without it the session's
    /// remembered "no warrant" would outlive the activation and the rest of
    /// the call would go uncovered.
    #[test]
    fn activating_a_warrant_mid_call_covers_the_rest_of_that_call() {
        let (manager, _iri, _audit) = manager();
        // One warrant, so the store is non-empty and matching actually runs.
        provision(&manager, DeliveryType::X2Only, None);

        let before = manager.check_session(
            "call-2@example.com",
            Some("sip:carol@example.com"),
            Some("<sip:dave@example.com>;tag=d"),
            Some("<sip:carol@example.com>"),
            None,
        );
        assert!(before.is_empty(), "nothing names these two yet");

        // The ADMF provisions a warrant on the calling party, mid-call.
        let d_id = DId::generate();
        manager
            .destinations()
            .create(DestinationDetails {
                d_id,
                friendly_name: None,
                delivery_type: DeliveryType::X2Only,
                delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 51)),
                    port: Port::Tcp(42070),
                }),
            })
            .expect("destination must provision");
        manager
            .tasks()
            .activate(TaskDetails {
                x_id: XId::generate(),
                target_identifiers: vec![TargetIdentifier::SipUri(
                    "sip:dave@example.com".to_string(),
                )],
                delivery_type: DeliveryType::X2Only,
                list_of_dids: vec![d_id],
                list_of_dsids: Vec::new(),
                list_of_mediation_details: Vec::new(),
                correlation_id: None,
                implicit_deactivation_allowed: None,
                product_id: None,
                list_of_service_types: Vec::new(),
            })
            .expect("task must provision");

        let after = manager.check_session(
            "call-2@example.com",
            Some("sip:carol@example.com"),
            Some("<sip:dave@example.com>;tag=d"),
            Some("<sip:carol@example.com>"),
            None,
        );
        assert_eq!(
            after.len(),
            1,
            "a warrant activated mid-call must cover the rest of that call, \
             not wait for the next one"
        );
    }

    /// The mirror: a deactivation must stop covering a live call.
    #[test]
    fn deactivating_a_warrant_mid_call_stops_covering_that_call() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);

        assert_eq!(
            manager
                .check_session(
                    "call-3@example.com",
                    Some("sip:bob@example.com"),
                    Some("<sip:alice@example.com>;tag=a"),
                    Some("<sip:bob@example.com>"),
                    None,
                )
                .len(),
            1
        );

        manager.tasks().deactivate(x_id).expect("must deactivate");

        assert!(
            manager
                .check_session(
                    "call-3@example.com",
                    Some("sip:bob@example.com"),
                    Some("<sip:alice@example.com>;tag=a"),
                    Some("<sip:bob@example.com>"),
                    None,
                )
                .is_empty(),
            "a withdrawn warrant must stop intercepting immediately"
        );
    }

    /// A `ModifyTask` has to be honoured on the next message, which is why the
    /// decision stores XIDs and re-reads the task rather than caching a copy.
    #[test]
    fn a_modified_task_is_read_fresh_on_the_next_message() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);

        let first = manager.check_session(
            "call-4@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );
        assert_eq!(first[0].task.details.delivery_type, DeliveryType::X2Only);

        let mut details = first[0].task.details.clone();
        details.delivery_type = DeliveryType::X2AndX3;
        manager.tasks().modify(details).expect("must modify");

        let second = manager.check_session(
            "call-4@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );
        assert_eq!(
            second[0].task.details.delivery_type,
            DeliveryType::X2AndX3,
            "the modification must be visible, not shadowed by a cached copy"
        );
        assert_eq!(second[0].task.details.x_id, x_id);
    }

    /// The key is chosen by whoever sent the message, so the map has to be
    /// bounded or a flood of distinct Call-IDs is a remote way to exhaust
    /// memory.
    #[test]
    fn remembered_sessions_are_bounded() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        // Cross the cap. Each of these matches nothing, which is the shape a
        // flood would take.
        for index in 0..(MAX_REMEMBERED_SESSIONS + 1_000) {
            manager.check_session(
                &format!("flood-{index}@attacker.invalid"),
                Some("sip:nobody@example.com"),
                Some("<sip:nobody@example.com>;tag=n"),
                Some("<sip:nobody@example.com>"),
                None,
            );
        }

        assert!(
            manager.remembered_session_count() <= MAX_REMEMBERED_SESSIONS,
            "the decision map grew past its cap ({})",
            manager.remembered_session_count()
        );
        // And it still works afterwards: degrading must not mean going deaf.
        assert_eq!(
            manager
                .check_session(
                    "real-call@example.com",
                    Some("sip:bob@example.com"),
                    Some("<sip:alice@example.com>;tag=a"),
                    Some("<sip:bob@example.com>"),
                    None,
                )
                .len(),
            1,
            "interception must survive the cache being cleared"
        );
    }

    #[test]
    fn a_message_is_recorded_once_and_a_resend_is_not() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        // A session has to be decided before anything is recorded against it.
        manager.check_session(
            "call-6@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );

        assert!(
            manager.record_message_once("call-6@example.com", 0xabc),
            "the first sight of a message is recorded"
        );
        assert!(
            !manager.record_message_once("call-6@example.com", 0xabc),
            "the same message again is a retransmission and must not be recorded twice"
        );
        assert!(
            manager.record_message_once("call-6@example.com", 0xdef),
            "a different message in the same session is still recorded"
        );

        // Another session's messages are independent, even at the same key.
        manager.check_session(
            "call-7@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );
        assert!(
            manager.record_message_once("call-7@example.com", 0xabc),
            "de-duplication is per session, not global"
        );
    }

    /// Past the per-session bound, recording must fail *open*.
    ///
    /// A duplicated record is recoverable at the mediation function; a dropped
    /// one is not. So the degraded mode has to be "record everything", which is
    /// the behaviour before de-duplication existed.
    #[test]
    fn de_duplication_stops_rather_than_starts_dropping_records() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        manager.check_session(
            "call-8@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );

        for key in 0..MAX_SEEN_PER_SESSION as u64 {
            assert!(manager.record_message_once("call-8@example.com", key));
        }
        // The set is full. Even a key it has definitely seen is now recorded
        // again rather than suppressed.
        assert!(
            manager.record_message_once("call-8@example.com", 0),
            "past the bound the element must record rather than risk dropping"
        );
    }

    /// A session nothing matched records nothing, so it de-duplicates nothing.
    #[test]
    fn an_unmatched_session_does_not_suppress_anything() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        assert!(manager.record_message_once("never-decided@example.com", 1));
        assert!(manager.record_message_once("never-decided@example.com", 1));
    }

    #[test]
    fn a_finished_session_is_forgotten() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        manager.check_session(
            "call-5@example.com",
            Some("sip:bob@example.com"),
            Some("<sip:alice@example.com>;tag=a"),
            Some("<sip:bob@example.com>"),
            None,
        );
        assert_eq!(manager.remembered_session_count(), 1);

        manager.forget_session("call-5@example.com");
        assert_eq!(manager.remembered_session_count(), 0);
    }

    #[test]
    fn a_matching_message_finds_its_warrant() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);

        let matched = manager.check_message(None, Some("sip:alice@example.com"), None, None);
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].task.details.x_id, x_id);
    }

    #[test]
    fn a_disabled_subsystem_matches_nothing() {
        let mut config = test_config();
        config.enabled = false;
        let (manager, _iri, _audit) = LiManager::new(config, 100, ContentCapability::Available);
        provision(&manager, DeliveryType::X2Only, None);

        assert!(manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .is_empty());
    }

    #[test]
    fn a_node_with_no_warrants_matches_nothing() {
        let (manager, _iri, _audit) = manager();
        assert!(manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .is_empty());
    }

    #[test]
    fn a_deactivated_warrant_stops_matching() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);
        assert!(!manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .is_empty());

        manager.tasks().deactivate(x_id).unwrap();
        assert!(manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .is_empty());
    }

    // -- correlation ------------------------------------------------------

    #[test]
    fn correlation_is_stable_for_one_call_id() {
        let first = correlation_from_call_id("abc123@example.com");
        let second = correlation_from_call_id("abc123@example.com");
        assert_eq!(first, second);
    }

    #[test]
    fn correlation_differs_between_call_ids() {
        assert_ne!(
            correlation_from_call_id("call-a@example.com"),
            correlation_from_call_id("call-b@example.com")
        );
    }

    #[test]
    fn correlation_is_never_zero() {
        // Zero is reserved for keepalive PDUs on X2/X3.
        for call_id in ["", "a", "call-1@x", "\0", &"z".repeat(512)] {
            assert_ne!(correlation_from_call_id(call_id), 0, "{call_id:?}");
        }
    }

    #[test]
    fn correlation_is_a_fixed_known_value() {
        // Pinned so a refactor cannot silently change the value the media
        // engine has to agree with.
        assert_eq!(correlation_from_call_id("test"), 0xf9e6_e6ef_197c_2b25);
    }

    #[test]
    fn a_provisioned_correlation_is_honoured_over_the_derived_one() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);

        let mut task = manager.tasks().get(x_id).unwrap();
        assert_eq!(
            manager.correlation_for(&task, "call-1@example.com"),
            correlation_from_call_id("call-1@example.com")
        );

        task.details.correlation_id = Some(4242);
        assert_eq!(manager.correlation_for(&task, "call-1@example.com"), 4242);
    }

    #[test]
    fn a_provisioned_zero_correlation_falls_back_to_the_derived_one() {
        // Zero is not usable on the wire, so it cannot be taken at face value.
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);
        let mut task = manager.tasks().get(x_id).unwrap();
        task.details.correlation_id = Some(0);
        assert_ne!(manager.correlation_for(&task, "call-1@example.com"), 0);
    }

    // -- LIID -------------------------------------------------------------

    #[test]
    fn the_liid_comes_from_mediation_details_when_provisioned() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, Some("LI-2026-0001"));
        let task = manager.tasks().get(x_id).unwrap();
        assert_eq!(LiManager::liid_for(&task), "LI-2026-0001");
    }

    #[test]
    fn the_liid_falls_back_to_the_xid_when_none_is_provisioned() {
        // A record must never be unattributable.
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);
        let task = manager.tasks().get(x_id).unwrap();
        assert_eq!(LiManager::liid_for(&task), x_id.to_string());
    }

    // -- IRI events --------------------------------------------------------

    #[tokio::test]
    async fn an_iri_event_carries_the_xid_liid_and_correlation() {
        let (manager, mut iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2AndX3, Some("LI-2026-0001"));
        let matched = manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .remove(0);

        let event = manager.build_iri_event(
            &matched,
            IriEventType::Begin,
            "call-1@example.com",
            "INVITE",
            None,
            "sip:alice@example.com",
            "sip:bob@example.com",
            Some("sip:bob@example.com".to_string()),
            None,
            None,
        );
        manager.emit_iri(event);

        let received = iri.recv().await.unwrap();
        assert_eq!(received.x_id, x_id);
        assert_eq!(received.liid, "LI-2026-0001");
        assert_eq!(
            received.correlation_id,
            correlation_from_call_id("call-1@example.com")
        );
        assert_ne!(received.correlation_id, 0);
        assert_eq!(received.event_type, IriEventType::Begin);
        assert_eq!(received.delivery_type, DeliveryType::X2AndX3);
    }

    #[test]
    fn an_iri_event_carries_only_the_destinations_the_warrant_named() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        // A second, unrelated destination that no task names.
        manager
            .destinations()
            .create(DestinationDetails {
                d_id: DId::generate(),
                friendly_name: None,
                delivery_type: DeliveryType::X2Only,
                delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                    address: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                    port: Port::Tcp(1234),
                }),
            })
            .unwrap();

        let matched = manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .remove(0);
        let event = manager.build_iri_event(
            &matched,
            IriEventType::Begin,
            "call-1@example.com",
            "INVITE",
            None,
            "sip:alice@example.com",
            "sip:bob@example.com",
            None,
            None,
            None,
        );
        assert_eq!(event.destinations.len(), 1);
        assert_eq!(event.destinations[0].to_string(), "192.0.2.50:42069");
    }

    #[test]
    fn an_x3_only_warrant_yields_no_x2_destinations() {
        // An X3Only task must not push IRI at an X2 collector.
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X3Only, None);
        let task = manager.tasks().get(x_id).unwrap();
        let content = manager.tasks().destinations_for_interface(x_id, true);
        assert_eq!(content.len(), 1);
        assert!(task.details.delivery_type.includes_content());
        assert!(!task.details.delivery_type.includes_iri());
    }

    #[tokio::test]
    async fn audit_entries_reach_the_trail() {
        let (manager, _iri, mut audit) = manager();
        let startup = audit.recv().await.unwrap();
        assert_eq!(startup.operation, AuditOperation::SystemStarted);

        manager.audit(
            AuditOperation::InterceptMatch,
            Some("task-1"),
            "matched".to_string(),
        );
        let entry = audit.recv().await.unwrap();
        assert_eq!(entry.operation, AuditOperation::InterceptMatch);
        assert_eq!(entry.subject.as_deref(), Some("task-1"));
    }

    // -- the content-capability gate ----------------------------------------

    #[test]
    fn backend_capability_maps_to_the_published_table() {
        // rtpengine and rtpproxy have no X3 framer at all.
        assert_eq!(
            LiManager::content_capability_for(MediaBackendKind::Rtpengine),
            ContentCapability::WrongBackend {
                backend: "rtpengine"
            }
        );
        assert_eq!(
            LiManager::content_capability_for(MediaBackendKind::Rtpproxy),
            ContentCapability::WrongBackend {
                backend: "rtpproxy"
            }
        );
        // The native engine is the only backend that can ever deliver content,
        // but it also needs a control verb to be told to. This assertion
        // tracks whichever of the two conditions is currently the binding one,
        // so it stays honest when the verb lands.
        let native = LiManager::content_capability_for(MediaBackendKind::SiphonRtp);
        if crate::li::x1::store::engine_supports_content() {
            assert_eq!(native, ContentCapability::Available);
        } else {
            assert_eq!(native, ContentCapability::EngineContractLacksVerb);
        }
    }

    #[test]
    fn a_content_warrant_cannot_be_provisioned_without_a_capable_backend() {
        let (manager, _iri, _audit) = LiManager::new(
            test_config(),
            100,
            LiManager::content_capability_for(MediaBackendKind::Rtpengine),
        );
        let d_id = DId::generate();
        manager
            .destinations()
            .create(DestinationDetails {
                d_id,
                friendly_name: None,
                delivery_type: DeliveryType::X2AndX3,
                delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                    address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                    port: Port::Tcp(42069),
                }),
            })
            .unwrap();

        let result = manager.tasks().activate(TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri("sip:alice@example.com".into())],
            delivery_type: DeliveryType::X2AndX3,
            list_of_dids: vec![d_id],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        });
        assert!(result.is_err(), "a content warrant must be refused here");
        assert!(manager.tasks().is_empty());
    }

    /// The task's own delivery type is what stops content being attached for an
    /// IRI-only warrant.
    ///
    /// Not the destination's: a destination may well be content-capable — the
    /// one this helper provisions is — and still be named by a warrant that
    /// only asks for signalling. The dispatcher checks the task first for
    /// exactly that reason.
    #[test]
    fn an_iri_only_warrant_does_not_ask_for_content() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);

        let task = manager.tasks().get(x_id).expect("task must exist");
        assert!(
            !task.details.delivery_type.includes_content(),
            "an X2Only warrant must not ask for content"
        );
        assert!(
            !manager
                .tasks()
                .destinations_for_interface(x_id, true)
                .is_empty(),
            "the destination is content-capable, which is why the task's own \
             delivery type has to be the gate"
        );
    }
}
