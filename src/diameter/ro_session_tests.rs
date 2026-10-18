//! Several independent credit-control sessions, with and without a call: the
//! session primitive behind `diameter.ro_session()`.
//!
//! Every assertion reads what a scripted OCS on a loopback socket actually
//! received — the decoded CCR and, where the header matters (the T flag on a
//! failover), the raw bytes.

use super::*;
use crate::diameter::codec::{
    self, encode_avp_grouped, encode_avp_u32, encode_avp_utf8, encode_diameter_message,
    FLAG_REQUEST, FLAG_RETRANSMITTED,
};
use crate::diameter::dictionary::avp;
use crate::diameter::peer::spawn_connection_tasks;
use crate::diameter::ro_test_support::{enabled_config, ims_information, ocs_peer_config};
use crate::diameter::DiameterClient;
use std::sync::Mutex as StdMutex;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// One CCR as the OCS saw it.
#[derive(Clone, Debug)]
struct Seen {
    flags: u8,
    end_to_end: u32,
    avps: serde_json::Value,
}

impl Seen {
    fn request_type(&self) -> u64 {
        self.avps["CC-Request-Type"].as_u64().unwrap_or(0)
    }
    fn request_number(&self) -> u64 {
        self.avps["CC-Request-Number"].as_u64().unwrap_or(u64::MAX)
    }
    fn session_id(&self) -> String {
        self.avps["Session-Id"].as_str().unwrap_or("").to_string()
    }
    fn subscriber(&self) -> String {
        self.avps["Subscription-Id"]["Subscription-Id-Data"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }
    fn used_seconds(&self) -> Option<u64> {
        self.avps
            .get("Multiple-Services-Credit-Control")
            .and_then(|m| m.get("Used-Service-Unit"))
            .and_then(|u| u.get("CC-Time"))
            .and_then(|v| v.as_u64())
    }
}

/// How the scripted OCS answers.
#[derive(Clone)]
struct Script {
    /// Answer at all. A silent OCS reads and never writes: the client's Tx
    /// timer is what ends the wait.
    answers: bool,
    grant_secs: u32,
    validity_secs: Option<u32>,
    /// Extra command-level AVPs on every CCA (CCFH, CC-Session-Failover).
    extra: Vec<u8>,
}

impl Default for Script {
    fn default() -> Self {
        Self {
            answers: true,
            grant_secs: 3600,
            validity_secs: None,
            extra: Vec::new(),
        }
    }
}

async fn scripted_ocs(script: Script) -> (Arc<DiameterPeer>, Arc<StdMutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let addr = listener.local_addr().expect("an address");
    let seen: Arc<StdMutex<Vec<Seen>>> = Arc::new(StdMutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
            let Some(message) = codec::decode_diameter(&bytes) else {
                continue;
            };
            if !message.is_request || message.command_code != dictionary::CMD_CREDIT_CONTROL {
                if !message.is_request {
                    continue;
                }
                let mut answer = bytes.clone();
                answer[4] &= !FLAG_REQUEST;
                let _ = write_half.write_all(&answer).await;
                continue;
            }
            let entry = Seen {
                flags: bytes[4],
                end_to_end: message.end_to_end,
                avps: message.avps.clone(),
            };
            log.lock().expect("log").push(entry.clone());
            if !script.answers {
                continue;
            }
            let mut avps = Vec::new();
            avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &entry.session_id()));
            avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
            avps.extend_from_slice(&encode_avp_u32(
                avp::CC_REQUEST_TYPE,
                entry.request_type() as u32,
            ));
            avps.extend_from_slice(&encode_avp_u32(
                avp::CC_REQUEST_NUMBER,
                entry.request_number() as u32,
            ));
            avps.extend_from_slice(&script.extra);
            if entry.request_type() != 3 {
                let mut mscc = encode_avp_grouped(
                    avp::GRANTED_SERVICE_UNIT,
                    &encode_avp_u32(avp::CC_TIME, script.grant_secs),
                );
                if let Some(validity) = script.validity_secs {
                    mscc.extend_from_slice(&encode_avp_u32(avp::VALIDITY_TIME, validity));
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
                message.hop_by_hop,
                message.end_to_end,
                &avps,
            );
            if write_half.write_all(&cca).await.is_err() {
                break;
            }
        }
    });
    let stream = TcpStream::connect(addr).await.expect("the OCS accepts");
    let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(16);
    // The receiver is dropped: these tests drive RAR/ASR through the handlers.
    let peer = spawn_connection_tasks(ocs_peer_config(), stream, incoming_tx);
    (peer, seen)
}

fn manager_of(peers: &[(&str, &Arc<DiameterPeer>)]) -> Arc<DiameterManager> {
    let manager = Arc::new(DiameterManager::new());
    for (name, peer) in peers {
        manager.register(
            name.to_string(),
            Arc::new(DiameterClient::new(Arc::clone(peer))),
        );
    }
    manager
}

fn seen(log: &Arc<StdMutex<Vec<Seen>>>) -> Vec<Seen> {
    log.lock().expect("log").clone()
}

async fn granted(service: &Arc<RoChargingService>, spec: RoSessionSpec) -> CcCreditSession {
    match service.open_session(spec).await {
        ChargeDecision::Granted(Some(session)) => session,
        ChargeDecision::Denied(code) => panic!("denied {code}"),
        _ => panic!("no session"),
    }
}

fn leg_data(role: ro::NodeRole, calling: &str, called: &str) -> ImsChargingData {
    ImsChargingData {
        calling_party: vec![calling.to_string()],
        called_party: Some(called.to_string()),
        role_of_node: Some(role),
        ims_charging_identifier: Some("icid-0001".to_string()),
        ..Default::default()
    }
}

async fn settle() {
    for _ in 0..50 {
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// ── several sessions, one call ──────────────────────────────────────────

/// A forwarded call: the caller's session and the forwarding user's are two
/// credit-control sessions, each with its own Session-Id, Subscription-Id and
/// Role-Of-Node, and ending one leaves the other running.
#[tokio::test]
async fn two_sessions_for_one_call_are_independent_on_the_wire() {
    let (peer, log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());

    let caller = granted(
        &service,
        service.session_spec(
            SubscriberId::sip_uri("sip:+15550100001@ims.example.net"),
            Some(leg_data(
                ro::NodeRole::OriginatingRole,
                "sip:+15550100001@ims.example.net",
                "sip:+15550100002@ims.example.net",
            )),
        ),
    )
    .await;
    let forwarder = granted(
        &service,
        service.session_spec(
            SubscriberId::sip_uri("sip:+15550100002@ims.example.net"),
            Some(leg_data(
                ro::NodeRole::ForwardingRole,
                "sip:+15550100002@ims.example.net",
                "sip:+15550100003@ims.example.net",
            )),
        ),
    )
    .await;
    assert_ne!(caller.session_id(), forwarder.session_id());
    assert_eq!(service.active_session_count(), 2);

    service.terminate_call(&forwarder, Some(0)).await;
    assert_eq!(
        service.active_session_count(),
        1,
        "only the forwarded leg ended"
    );
    assert!(caller.is_open());

    let requests = seen(&log);
    let initials: Vec<&Seen> = requests.iter().filter(|r| r.request_type() == 1).collect();
    assert_eq!(initials.len(), 2);
    assert_eq!(initials[0].subscriber(), "sip:+15550100001@ims.example.net");
    assert_eq!(initials[1].subscriber(), "sip:+15550100002@ims.example.net");
    let roles: Vec<u64> = initials
        .iter()
        .map(|r| {
            ims_information(&r.avps)
                .and_then(|i| i.get("Role-of-Node"))
                .and_then(|v| v.as_u64())
                .unwrap_or(99)
        })
        .collect();
    assert_eq!(
        roles,
        vec![0, 2],
        "originating, then forwarding (TS 32.299 §7.2.177)"
    );
    let terminations: Vec<&Seen> = requests.iter().filter(|r| r.request_type() == 3).collect();
    assert_eq!(terminations.len(), 1);
    assert_eq!(terminations[0].session_id(), forwarder.session_id());
    assert_eq!(terminations[0].request_number(), 1);

    service.terminate_call(&caller, Some(0)).await;
    assert_eq!(service.active_session_count(), 0);
}

/// Sessions bound to a call all end with it, under its cause; one ended on its
/// own leaves the binding.
#[tokio::test]
async fn sessions_bound_to_a_call_end_with_it() {
    let (peer, log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());
    let mut sessions = Vec::new();
    for party in ["+15550100001", "+15550100002", "+15550100003"] {
        let session = granted(
            &service,
            service.session_spec(SubscriberId::msisdn(party), None),
        )
        .await;
        assert!(service.bind_call(&session, "call-uuid-1", "sip-call-1"));
        assert_eq!(session.teardown_call().as_deref(), Some("sip-call-1"));
        sessions.push(session);
    }
    assert_eq!(service.bound_sessions("call-uuid-1").len(), 3);

    service.terminate_call(&sessions[0], Some(0)).await;
    assert_eq!(
        service.bound_sessions("call-uuid-1").len(),
        2,
        "a session ended on its own leaves the binding"
    );

    service.end_bound("call-uuid-1", Some(-486)).await;
    assert_eq!(service.active_session_count(), 0);
    assert!(service.bound_call_ids().is_empty());
    let causes: Vec<i64> = seen(&log)
        .iter()
        .filter(|r| r.request_type() == 3)
        .filter_map(|r| ims_information(&r.avps)?.get("Cause-Code")?.as_i64())
        .collect();
    assert_eq!(
        causes.len(),
        0,
        "no IMS-Information was given, so none is sent"
    );
    let terminated = seen(&log).iter().filter(|r| r.request_type() == 3).count();
    assert_eq!(terminated, 3);
}

// ── a session with no call ──────────────────────────────────────────────

/// An SCP's session: no SIP call, found by its dialogue key, usage reported
/// by the owner as a cumulative figure and sent as the difference.
#[tokio::test]
async fn an_externally_metered_session_reports_the_difference_of_cumulative_usage() {
    let (peer, log) = scripted_ocs(Script {
        grant_secs: 20,
        ..Script::default()
    })
    .await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());
    let mut spec = service.session_spec(SubscriberId::msisdn("15550100001"), None);
    spec.metering = Metering::External;
    spec.key = Some("tcap-0x1a2b".to_string());
    spec.service_context_id = "32276@3gpp.org".to_string();
    let session = granted(&service, spec).await;
    assert!(service.session_by_key("tcap-0x1a2b").is_some());

    let mut duplicate = service.session_spec(SubscriberId::msisdn("15550100001"), None);
    duplicate.key = Some("tcap-0x1a2b".to_string());
    assert!(
        matches!(
            service.open_session(duplicate).await,
            ChargeDecision::Denied(_)
        ),
        "a key names one live session"
    );

    let answer = service.report_usage(&session, 10).await.expect("an answer");
    assert!(answer.is_success());
    assert_eq!(session.grant().granted_time, Some(20));
    service.report_usage(&session, 25).await.expect("an answer");
    service.terminate_with_usage(&session, 40, Some(0)).await;
    assert!(service.session_by_key("tcap-0x1a2b").is_none());

    let requests = seen(&log);
    let used: Vec<(u64, Option<u64>)> = requests
        .iter()
        .map(|r| (r.request_type(), r.used_seconds()))
        .collect();
    assert_eq!(
        used,
        vec![(1, None), (2, Some(10)), (2, Some(15)), (3, Some(15))],
        "each request carries only what the previous one did not"
    );
    assert!(requests
        .iter()
        .all(|r| r.avps["Service-Context-Id"] == "32276@3gpp.org"));
    assert!(
        requests
            .iter()
            .all(|r| r.avps.get("Service-Information").is_none()),
        "a session given no IMS-Information sends none"
    );
}

// ── re-authorization deadline ───────────────────────────────────────────

fn answer_with(
    granted: Option<u32>,
    threshold: Option<u32>,
    validity: Option<u32>,
) -> CreditControlAnswer {
    CreditControlAnswer {
        result_code: 2001,
        request_type: Some(1),
        request_number: Some(0),
        granted_time: granted,
        granted_total_octets: None,
        validity_time: validity,
        final_unit_action: None,
        session_id: None,
        time_quota_threshold: threshold,
        redirect_server_address: None,
        credit_control_failure_handling: None,
        cc_session_failover: None,
        tariff_time_change: None,
        free_format_data: None,
    }
}

#[test]
fn the_reauthorization_is_due_at_the_threshold_or_the_validity_whichever_is_first() {
    assert_eq!(reauth_after(&answer_with(Some(60), None, None), 30), 60);
    assert_eq!(
        reauth_after(&answer_with(Some(60), Some(10), None), 30),
        50,
        "TS 32.299 §7.2.229: re-authorise with Time-Quota-Threshold seconds left"
    );
    assert_eq!(
        reauth_after(&answer_with(Some(60), Some(10), Some(20)), 30),
        20,
        "RFC 8506 §5.1.2: the Validity-Time runs regardless of usage"
    );
    assert_eq!(reauth_after(&answer_with(None, None, Some(40)), 30), 40);
    assert_eq!(reauth_after(&answer_with(None, None, None), 30), 30);
    assert_eq!(
        reauth_after(&answer_with(Some(8), Some(8), None), 30),
        MIN_REAUTH_SECS,
        "never faster than the floor"
    );
}

// ── requests from the OCS ───────────────────────────────────────────────

/// RFC 8506 §5.5: a RAR is answered 2001 and the session asks for a new grant
/// at once, without waiting for its own.
#[tokio::test]
async fn a_rar_sends_the_update_now() {
    let (peer, log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());
    let session = granted(
        &service,
        service.session_spec(SubscriberId::msisdn("15550100001"), None),
    )
    .await;
    assert_eq!(
        service.handle_rar("no-such-session"),
        None,
        "not ours: passed on"
    );
    assert_eq!(service.handle_rar(session.session_id()), Some(2001));
    settle().await;
    let updates: Vec<Seen> = seen(&log)
        .into_iter()
        .filter(|r| r.request_type() == 2)
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "one CCR-UPDATE for the RAR, the grant is an hour"
    );
    assert_eq!(updates[0].session_id(), session.session_id());
    assert_eq!(updates[0].request_number(), 1);
    service.terminate_call(&session, Some(0)).await;
}

/// An externally metered session is told to report instead.
#[tokio::test]
async fn a_rar_on_an_external_session_asks_its_owner_to_report() {
    let (peer, log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());
    let events: Arc<StdMutex<Vec<RoSessionEvent>>> = Arc::default();
    let sink = Arc::clone(&events);
    let mut spec = service.session_spec(SubscriberId::msisdn("15550100001"), None);
    spec.metering = Metering::External;
    spec.event_hook = Some(Arc::new(move |_session, event| {
        sink.lock().expect("events").push(event.clone());
    }));
    let session = granted(&service, spec).await;
    assert_eq!(service.handle_rar(session.session_id()), Some(2001));
    settle().await;
    let kinds: Vec<RoEventKind> = events
        .lock()
        .expect("events")
        .iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds, vec![RoEventKind::Reauthorize]);
    assert_eq!(
        seen(&log).iter().filter(|r| r.request_type() == 2).count(),
        0,
        "the owner reports, siphon does not guess its usage"
    );
    service.terminate_with_usage(&session, 0, Some(0)).await;
}

/// RFC 8506 §5.5: an ASR ends the session — the bound call torn down, the
/// owner told, a CCR-TERMINATION sent — and leaves every other session alone.
#[tokio::test]
async fn an_asr_ends_only_its_session() {
    let (peer, log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());
    let torn_down: Arc<StdMutex<Vec<(String, String)>>> = Arc::default();
    let sink = Arc::clone(&torn_down);
    service.set_teardown_hook(Arc::new(move |call, reason| {
        sink.lock()
            .expect("teardowns")
            .push((call.to_string(), reason.to_string()));
    }));
    let events: Arc<StdMutex<Vec<RoEventKind>>> = Arc::default();
    let event_sink = Arc::clone(&events);
    let mut spec = service.session_spec(SubscriberId::msisdn("15550100001"), None);
    spec.teardown_call = Some("sip-call-a".to_string());
    spec.event_hook = Some(Arc::new(move |_session, event| {
        event_sink.lock().expect("events").push(event.kind);
    }));
    let aborted = granted(&service, spec).await;
    let other = granted(
        &service,
        service.session_spec(SubscriberId::msisdn("15550100002"), None),
    )
    .await;

    assert_eq!(service.handle_asr(aborted.session_id()), Some(2001));
    settle().await;
    assert!(!aborted.is_open());
    assert!(other.is_open());
    assert_eq!(service.active_session_count(), 1);
    assert_eq!(
        torn_down.lock().expect("teardowns").clone(),
        vec![(
            "sip-call-a".to_string(),
            "aborted by the charging system".to_string()
        )]
    );
    assert_eq!(
        events.lock().expect("events").clone(),
        vec![RoEventKind::Aborted]
    );
    let terminations: Vec<Seen> = seen(&log)
        .into_iter()
        .filter(|r| r.request_type() == 3)
        .collect();
    assert_eq!(terminations.len(), 1);
    assert_eq!(terminations[0].session_id(), aborted.session_id());
    service.terminate_call(&other, Some(0)).await;
}

// ── failure handling and failover ───────────────────────────────────────

fn failover_config(on_ocs_failure: &str, session_failover: bool) -> RoConfig {
    RoConfig {
        on_ocs_failure: on_ocs_failure.to_string(),
        session_failover,
        tx_timeout_ms: 300,
        peer: Some("a".to_string()),
        ..enabled_config()
    }
}

/// RFC 8506 §5.7: with failover allowed, a request the server does not answer
/// within Tx goes to the alternate server, same End-to-End Identifier, same
/// Session-Id and CC-Request-Number, T flag set — and the session stays there.
#[tokio::test]
async fn an_unanswered_request_fails_over_with_the_t_flag() {
    let (silent, silent_log) = scripted_ocs(Script {
        answers: false,
        ..Script::default()
    })
    .await;
    let (alternate, alternate_log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(
        manager_of(&[("a", &silent), ("b", &alternate)]),
        failover_config("retry_and_terminate", true),
    );
    let session = granted(
        &service,
        service.session_spec(SubscriberId::msisdn("15550100001"), None),
    )
    .await;

    let first = seen(&silent_log);
    let retried = seen(&alternate_log);
    assert_eq!(first.len(), 1);
    assert_eq!(retried.len(), 1);
    assert_eq!(first[0].flags & FLAG_RETRANSMITTED, 0);
    assert_ne!(
        retried[0].flags & FLAG_RETRANSMITTED,
        0,
        "T flag on the re-sent request"
    );
    assert_eq!(first[0].end_to_end, retried[0].end_to_end);
    assert_eq!(first[0].session_id(), retried[0].session_id());
    assert_eq!(retried[0].session_id(), session.session_id());
    assert_eq!(retried[0].request_number(), 0);

    service.terminate_call(&session, Some(0)).await;
    assert_eq!(
        seen(&silent_log).len(),
        1,
        "the session moved to the server that answered"
    );
    assert_eq!(seen(&alternate_log).last().map(Seen::request_type), Some(3));
}

/// TERMINATE never fails over, and an unanswered CCR-INITIAL is refused.
#[tokio::test]
async fn terminate_does_not_fail_over() {
    let (silent, _silent_log) = scripted_ocs(Script {
        answers: false,
        ..Script::default()
    })
    .await;
    let (alternate, alternate_log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(
        manager_of(&[("a", &silent), ("b", &alternate)]),
        failover_config("terminate", true),
    );
    let decision = service
        .open_session(service.session_spec(SubscriberId::msisdn("15550100001"), None))
        .await;
    assert!(matches!(
        decision,
        ChargeDecision::Denied(dictionary::DIAMETER_UNABLE_TO_DELIVER)
    ));
    assert!(seen(&alternate_log).is_empty());
}

/// CC-Session-Failover absent means FAILOVER_NOT_SUPPORTED: no move, even
/// under CONTINUE.
#[tokio::test]
async fn no_failover_unless_the_session_allows_it() {
    let (silent, _silent_log) = scripted_ocs(Script {
        answers: false,
        ..Script::default()
    })
    .await;
    let (alternate, alternate_log) = scripted_ocs(Script::default()).await;
    let service = RoChargingService::new(
        manager_of(&[("a", &silent), ("b", &alternate)]),
        failover_config("continue", false),
    );
    let decision = service
        .open_session(service.session_spec(SubscriberId::msisdn("15550100001"), None))
        .await;
    assert!(
        matches!(decision, ChargeDecision::AllowUncharged),
        "CONTINUE: the service goes ahead uncharged"
    );
    assert!(seen(&alternate_log).is_empty());
}

/// RFC 8506 §5.7: Credit-Control-Failure-Handling and CC-Session-Failover in
/// a CCA override the configured defaults for the rest of the session.
#[tokio::test]
async fn the_answer_sets_the_failure_handling_of_its_session() {
    let mut extra = encode_avp_u32(avp::CREDIT_CONTROL_FAILURE_HANDLING, CCFH_CONTINUE);
    extra.extend_from_slice(&encode_avp_u32(avp::CC_SESSION_FAILOVER, 1));
    let (peer, _log) = scripted_ocs(Script {
        extra,
        ..Script::default()
    })
    .await;
    let service = RoChargingService::new(
        manager_of(&[("a", &peer)]),
        failover_config("terminate", false),
    );
    let session = granted(
        &service,
        service.session_spec(SubscriberId::msisdn("15550100001"), None),
    )
    .await;
    assert_eq!(session.failure_handling(), CCFH_CONTINUE);
    assert!(session.inner.failover_supported.load(Ordering::Relaxed));
    service.terminate_call(&session, Some(0)).await;
}

// ── Validity-Time on an external session ────────────────────────────────

#[tokio::test(start_paused = true)]
async fn an_expired_validity_time_asks_the_external_owner_to_report() {
    let (peer, _log) = scripted_ocs(Script {
        validity_secs: Some(30),
        ..Script::default()
    })
    .await;
    let service = RoChargingService::new(manager_of(&[("ocs", &peer)]), enabled_config());
    let events: Arc<StdMutex<Vec<String>>> = Arc::default();
    let sink = Arc::clone(&events);
    let mut spec = service.session_spec(SubscriberId::msisdn("15550100001"), None);
    spec.metering = Metering::External;
    spec.event_hook = Some(Arc::new(move |_session, event| {
        sink.lock().expect("events").push(event.reason.clone());
    }));
    let session = granted(&service, spec).await;
    for _ in 0..10 {
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
    }
    assert_eq!(
        events.lock().expect("events").clone(),
        vec!["validity time expired".to_string()]
    );
    service.terminate_with_usage(&session, 0, Some(0)).await;
}

// ── wire bytes for an independent decoder ───────────────────────────────

/// Write the CCRs of two sessions and the answers to a RAR and an ASR as a
/// hex dump for `scripts/validate_ro_sessions.sh`, which has tshark decode
/// them. Runs only when SIPHON_RO_SESSIONS_HEX_OUT names a file.
#[tokio::test]
async fn emit_ro_sessions_for_external_dissection() {
    let Ok(path) = std::env::var("SIPHON_RO_SESSIONS_HEX_OUT") else {
        return;
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let addr = listener.local_addr().expect("an address");
    let frames: Arc<StdMutex<Vec<Vec<u8>>>> = Arc::default();
    let log = Arc::clone(&frames);
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
            let Some(message) = codec::decode_diameter(&bytes) else {
                continue;
            };
            if !message.is_request {
                continue;
            }
            log.lock().expect("frames").push(bytes.clone());
            let session_id = message.avps["Session-Id"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let mut avps = encode_avp_utf8(avp::SESSION_ID, &session_id);
            avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
            avps.extend_from_slice(&encode_avp_u32(
                avp::CC_REQUEST_TYPE,
                message.avps["CC-Request-Type"].as_u64().unwrap_or(1) as u32,
            ));
            avps.extend_from_slice(&encode_avp_u32(
                avp::CC_REQUEST_NUMBER,
                message.avps["CC-Request-Number"].as_u64().unwrap_or(0) as u32,
            ));
            let mut mscc = encode_avp_grouped(
                avp::GRANTED_SERVICE_UNIT,
                &encode_avp_u32(avp::CC_TIME, 3600),
            );
            mscc.extend_from_slice(&codec::encode_avp_u32_3gpp(avp::TIME_QUOTA_THRESHOLD, 10));
            avps.extend_from_slice(&encode_avp_grouped(
                avp::MULTIPLE_SERVICES_CREDIT_CONTROL,
                &mscc,
            ));
            let cca = encode_diameter_message(
                0,
                dictionary::CMD_CREDIT_CONTROL,
                dictionary::RO_APP_ID,
                message.hop_by_hop,
                message.end_to_end,
                &avps,
            );
            let _ = write_half.write_all(&cca).await;
        }
    });
    let stream = TcpStream::connect(addr).await.expect("accepts");
    let (incoming_tx, _incoming_rx) = tokio::sync::mpsc::channel(16);
    let peer = spawn_connection_tasks(ocs_peer_config(), stream, incoming_tx);
    let service = RoChargingService::new(
        manager_of(&[("ocs", &peer)]),
        RoConfig {
            node_functionality: "as".to_string(),
            ..enabled_config()
        },
    );

    let caller = granted(
        &service,
        service.session_spec(
            SubscriberId::sip_uri("sip:+15550100001@ims.example.net"),
            Some(leg_data(
                ro::NodeRole::OriginatingRole,
                "sip:+15550100001@ims.example.net",
                "sip:+15550100002@ims.example.net",
            )),
        ),
    )
    .await;
    let mut forwarded = service.session_spec(
        SubscriberId::msisdn("15550100002"),
        Some(leg_data(
            ro::NodeRole::ForwardingRole,
            "sip:+15550100002@ims.example.net",
            "sip:+15550100003@ims.example.net",
        )),
    );
    forwarded.metering = Metering::External;
    let forwarder = granted(&service, forwarded).await;
    service
        .report_usage(&forwarder, 12)
        .await
        .expect("an answer");
    service.terminate_with_usage(&forwarder, 20, Some(0)).await;
    service.terminate_call(&caller, Some(-486)).await;

    // A Proxy Function's session (TS 32.276) for a forwarded CS call (MF):
    // MSISDN and IMSI, VCS-Information, Node-Functionality 16, Role-Of-Node
    // FORWARDING, keyed by its CAMEL dialogue, no SIP call behind it. The
    // release adds ISUP-Cause and Stop-Time to the CCR-TERMINATION only.
    let mut camel = service.session_spec(
        SubscriberId::msisdn("15550100004"),
        Some(ImsChargingData {
            role_of_node: Some(ro::NodeRole::ForwardingRole),
            node_functionality: Some(NodeFunctionality::ProxyFunction),
            ..Default::default()
        }),
    );
    camel.additional_subscribers = vec![SubscriberId::imsi("001010000000004")];
    camel.service_context_id = "32276@3gpp.org".to_string();
    camel.metering = Metering::External;
    camel.key = Some("dialogue-0042".to_string());
    camel.vcs_data = Some(ro::VcsInformation {
        msc_address: Some(vec![0x51, 0x55, 0x10, 0x00, 0xf9]),
        network_call_reference_number: Some(vec![0x01, 0x02, 0x03, 0x04]),
        basic_service_code: Some(ro::BasicServiceCode {
            bearer_service: None,
            teleservice: Some(vec![0x11]),
        }),
        vlr_number: Some(vec![0x51, 0x55, 0x10, 0x00, 0xf8]),
        start_time: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000)),
        ..Default::default()
    });
    let camel = granted(&service, camel).await;
    assert!(
        service.session_by_key("dialogue-0042").is_some(),
        "filed under its dialogue"
    );
    service
        .terminate_with(
            &camel,
            Some(30),
            Some(0),
            Some(ro::VcsInformation {
                isup_cause: Some(ro::IsupCause {
                    location: Some(4),
                    value: Some(16),
                    diagnostics: None,
                }),
                stop_time: Some(
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_042),
                ),
                ..Default::default()
            }),
        )
        .await;
    assert!(service.session_by_key("dialogue-0042").is_none());

    let mut dump = String::new();
    let mut frames = frames.lock().expect("frames").clone();
    frames.push(ro::build_session_answer(
        dictionary::CMD_RE_AUTH,
        caller.session_id(),
        2001,
        "siphon.test",
        "test",
        7,
        8,
        true,
    ));
    frames.push(ro::build_session_answer(
        dictionary::CMD_ABORT_SESSION,
        "unknown;1;2",
        dictionary::DIAMETER_UNKNOWN_SESSION_ID,
        "siphon.test",
        "test",
        9,
        10,
        true,
    ));
    for frame in frames {
        for (offset, chunk) in frame.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        dump.push('\n');
    }
    std::fs::write(path, dump).expect("the hex dump is written");
}
