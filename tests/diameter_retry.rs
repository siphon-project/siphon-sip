//! Sending a request to another peer of its route, once (3004, 3002, timeout,
//! a peer gone SUSPECT, an abated request), over real loopback connections.
//! The far ends are raw sockets that count the requests they receive.

#![allow(clippy::disallowed_methods)] // test runtime may block

use siphon::diameter::codec::{self, Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
use siphon::diameter::dictionary::{self, avp};
use siphon::diameter::forward;
use siphon::diameter::lifecycle::PeerLifecycle;
use siphon::diameter::overload::{self, Olr, Overload, ReportType};
use siphon::diameter::peer::{self, PeerConfig};
use siphon::diameter::retry::{send_routed, RetryPolicy, RetryRule};
use siphon::diameter::DiameterClient;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const S6A: u32 = dictionary::S6A_APP_ID;
const GY: u32 = 4;

fn config(origin_host: &str, port: u16) -> PeerConfig {
    PeerConfig {
        host: "127.0.0.1".to_string(),
        port,
        origin_host: origin_host.to_string(),
        origin_realm: "example.org".to_string(),
        destination_host: None,
        destination_realm: "example.org".to_string(),
        local_ip: "127.0.0.1".parse().expect("a literal address"),
        application_ids: vec![],
        watchdog_interval: 3600,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: PeerLifecycle::default(),
        product_name: "SIPhon".to_string(),
        firmware_revision: 1,
    }
}

#[derive(Clone, Copy)]
enum Behaviour {
    Answer(u32),
    /// Answers the capabilities exchange and nothing else.
    Silent,
}

struct Far {
    requests: Arc<AtomicUsize>,
    report: Arc<std::sync::Mutex<Option<Olr>>>,
}

/// A raw far end; returns the connected client of the node under test.
async fn far(
    name: &'static str,
    behaviour: Behaviour,
    watchdog_ms: Option<u64>,
) -> (Arc<DiameterClient>, Far) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let requests = Arc::new(AtomicUsize::new(0));
    let report = Arc::new(std::sync::Mutex::new(None::<Olr>));
    let counted = Arc::clone(&requests);
    let reported = Arc::clone(&report);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = tokio::io::BufReader::new(read_half);
        while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
            let Ok(request) = DiameterMsg::from_wire(&bytes) else {
                break;
            };
            if request.command_code == dictionary::CMD_CAPABILITIES_EXCHANGE {
                let cea = peer::build_cea(
                    &config(name, 0),
                    dictionary::DIAMETER_SUCCESS,
                    request.hop_by_hop,
                    request.end_to_end,
                );
                if write_half.write_all(&cea).await.is_err() {
                    break;
                }
                continue;
            }
            if request.application_id == 0 {
                continue;
            }
            counted.fetch_add(1, Ordering::SeqCst);
            let Behaviour::Answer(code) = behaviour else {
                continue;
            };
            let mut answer = forward::build_answer(&request, name, "example.org", code, None);
            if let Some(olr) = reported.lock().expect("report").take() {
                answer.avps.push(overload::olr_avp(&olr));
            }
            if write_half.write_all(&answer.to_wire()).await.is_err() {
                break;
            }
        }
    });
    let mut dial = config("node.example.org", port);
    dial.lifecycle.watchdog_interval_ms = watchdog_ms;
    let (peer, incoming) = peer::connect(dial).await.expect("dial");
    std::mem::forget(incoming);
    (
        Arc::new(DiameterClient::new(peer)),
        Far { requests, report },
    )
}

fn request(client: &DiameterClient, application: u32, command: u32) -> Vec<u8> {
    DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code: command,
        application_id: application,
        hop_by_hop: client.peer().next_hbh(),
        end_to_end: client.peer().next_e2e(),
        avps: vec![
            Avp::utf8(avp::SESSION_ID, 0, "node.example.org;1;1"),
            Avp::utf8(avp::ORIGIN_HOST, 0, "node.example.org"),
            Avp::utf8(avp::ORIGIN_REALM, 0, "example.org"),
            Avp::utf8(avp::DESTINATION_REALM, 0, "example.org"),
        ],
    }
    .to_wire()
}

fn policy(application: u32, timeout: bool, divert: bool) -> RetryPolicy {
    RetryPolicy {
        rules: vec![RetryRule {
            application_id: application,
            commands: vec![],
            too_busy: true,
            unable_to_deliver: true,
            timeout,
        }],
        divert_abated: divert,
    }
}

fn result_code(answer: &codec::DiameterMessage) -> u64 {
    answer
        .avps
        .get("Result-Code")
        .and_then(serde_json::Value::as_u64)
        .expect("a Result-Code")
}

async fn route(
    policy: &RetryPolicy,
    first: &Arc<DiameterClient>,
    alternates: &[Arc<DiameterClient>],
    application: u32,
    command: u32,
    timeout: Duration,
) -> Result<codec::DiameterMessage, String> {
    send_routed(
        policy,
        first,
        alternates,
        request(first, application, command),
        timeout,
        overload::Origin::Local,
    )
    .await
}

#[tokio::test]
async fn a_request_goes_once_to_another_peer_when_the_first_cannot_serve_it() {
    overload::install(Overload::new(true, None));
    let wait = Duration::from_secs(5);

    // 3004 on the first peer, 2001 on the second: the second answers.
    let (a, far_a) = far("a.example.org", Behaviour::Answer(3004), None).await;
    let (b, far_b) = far("b.example.org", Behaviour::Answer(2001), None).await;
    let answer = route(
        &policy(S6A, false, false),
        &a,
        &[Arc::clone(&b)],
        S6A,
        318,
        wait,
    )
    .await
    .expect("answered");
    assert_eq!(result_code(&answer), 2001);
    assert_eq!(far_a.requests.load(Ordering::SeqCst), 1);
    assert_eq!(far_b.requests.load(Ordering::SeqCst), 1);

    // 3002 is retried too.
    let (a, far_a) = far("a2.example.org", Behaviour::Answer(3002), None).await;
    let answer = route(
        &policy(S6A, false, false),
        &a,
        &[Arc::clone(&b)],
        S6A,
        318,
        wait,
    )
    .await
    .expect("answered");
    assert_eq!(result_code(&answer), 2001);
    assert_eq!(far_a.requests.load(Ordering::SeqCst), 1);

    // Both busy, a third available: tried once more, never twice.
    let (a, far_a) = far("a3.example.org", Behaviour::Answer(3004), None).await;
    let (busy_b, far_busy_b) = far("b3.example.org", Behaviour::Answer(3004), None).await;
    let (c, far_c) = far("c3.example.org", Behaviour::Answer(2001), None).await;
    let answer = route(
        &policy(S6A, false, false),
        &a,
        &[Arc::clone(&busy_b), Arc::clone(&c)],
        S6A,
        318,
        wait,
    )
    .await
    .expect("answered");
    assert_eq!(result_code(&answer), 3004, "the answer of the one retry");
    assert_eq!(far_a.requests.load(Ordering::SeqCst), 1);
    assert_eq!(far_busy_b.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        far_c.requests.load(Ordering::SeqCst),
        0,
        "bounded to one retry"
    );

    // Credit control is not repeated unless the entry names it.
    let (a, far_a) = far("a4.example.org", Behaviour::Answer(3004), None).await;
    let (b4, far_b4) = far("b4.example.org", Behaviour::Answer(2001), None).await;
    let answer = route(
        &policy(GY, false, false),
        &a,
        &[Arc::clone(&b4)],
        GY,
        272,
        wait,
    )
    .await
    .expect("answered");
    assert_eq!(result_code(&answer), 3004);
    assert_eq!(far_a.requests.load(Ordering::SeqCst), 1);
    assert_eq!(far_b4.requests.load(Ordering::SeqCst), 0);
    let named = RetryPolicy {
        rules: vec![RetryRule {
            application_id: GY,
            commands: vec![272],
            too_busy: true,
            unable_to_deliver: true,
            timeout: false,
        }],
        divert_abated: false,
    };
    let answer = route(&named, &a, &[Arc::clone(&b4)], GY, 272, wait)
        .await
        .expect("answered");
    assert_eq!(result_code(&answer), 2001);

    // No entry for the application: nothing is retried.
    let answer = route(
        &RetryPolicy::default(),
        &a,
        &[Arc::clone(&b4)],
        S6A,
        318,
        wait,
    )
    .await
    .expect("answered");
    assert_eq!(result_code(&answer), 3004);

    // A timeout is retried only where the entry allows it.
    let (silent, far_silent) = far("s5.example.org", Behaviour::Silent, None).await;
    let (b5, _far_b5) = far("b5.example.org", Behaviour::Answer(2001), None).await;
    let short = Duration::from_millis(300);
    let error = route(
        &policy(S6A, false, false),
        &silent,
        &[Arc::clone(&b5)],
        S6A,
        318,
        short,
    )
    .await
    .expect_err("no answer in time");
    assert!(error.contains("timed out"), "{error}");
    let answer = route(
        &policy(S6A, true, false),
        &silent,
        &[Arc::clone(&b5)],
        S6A,
        318,
        short,
    )
    .await
    .expect("answered by the second peer");
    assert_eq!(result_code(&answer), 2001);
    assert_eq!(far_silent.requests.load(Ordering::SeqCst), 2);

    // A peer that turns SUSPECT while the request waits fails it at once, and
    // the second peer answers: failover, not a wait for the long timeout.
    let (quiet, _far_quiet) = far("q6.example.org", Behaviour::Silent, Some(100)).await;
    let (b6, _far_b6) = far("b6.example.org", Behaviour::Answer(2001), None).await;
    let started = std::time::Instant::now();
    let answer = route(
        &policy(S6A, false, false),
        &quiet,
        &[Arc::clone(&b6)],
        S6A,
        318,
        Duration::from_secs(20),
    )
    .await
    .expect("answered by the second peer");
    assert_eq!(result_code(&answer), 2001);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "failed over on SUSPECT"
    );

    // An abated request: failed here, or diverted, per the policy.
    let (reporting, far_reporting) = far("r7.example.org", Behaviour::Answer(2001), None).await;
    let (b7, far_b7) = far("b7.example.org", Behaviour::Answer(2001), None).await;
    *far_reporting.report.lock().expect("report") = Some(Olr {
        sequence: 1,
        report_type: ReportType::Host,
        validity_secs: 30,
        reduction_percentage: 100,
    });
    route(&policy(S6A, false, false), &reporting, &[], S6A, 318, wait)
        .await
        .expect("the answer that carries the report");
    let error = route(
        &policy(S6A, false, false),
        &reporting,
        &[Arc::clone(&b7)],
        S6A,
        318,
        wait,
    )
    .await
    .expect_err("abated");
    assert!(overload::is_abated(&error));
    assert_eq!(
        far_b7.requests.load(Ordering::SeqCst),
        0,
        "reject does not divert"
    );
    let answer = route(
        &policy(S6A, false, true),
        &reporting,
        &[Arc::clone(&b7)],
        S6A,
        318,
        wait,
    )
    .await
    .expect("diverted");
    assert_eq!(result_code(&answer), 2001);
    assert_eq!(far_b7.requests.load(Ordering::SeqCst), 1);
    let error = route(&policy(S6A, false, true), &reporting, &[], S6A, 318, wait)
        .await
        .expect_err("abated with nowhere to go");
    assert!(overload::is_abated(&error));
    assert_eq!(
        far_reporting.requests.load(Ordering::SeqCst),
        1,
        "only the first reached it"
    );
}
