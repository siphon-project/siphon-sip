//! The DOIC agent (RFC 7683 section 5.3) over real loopback connections: a
//! relay in front of two backends. The far ends are raw sockets that count the
//! requests they receive, and report overload when told to.

#![allow(clippy::disallowed_methods)] // test runtime may block

use siphon::diameter::codec::{self, Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
use siphon::diameter::dictionary::{self, avp};
use siphon::diameter::forward;
use siphon::diameter::lifecycle::PeerLifecycle;
use siphon::diameter::overload::{self, Olr, Overload, ReportType};
use siphon::diameter::overload_agent::{relay, Target};
use siphon::diameter::peer::{self, PeerConfig};
use siphon::diameter::retry::RetryPolicy;
use siphon::diameter::DiameterClient;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

const S6A: u32 = dictionary::S6A_APP_ID;

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
}

struct Far {
    requests: Arc<AtomicUsize>,
    /// Requests that arrived with OC-Supported-Features.
    advertised: Arc<AtomicUsize>,
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
    let advertised = Arc::new(AtomicUsize::new(0));
    let report = Arc::new(std::sync::Mutex::new(None::<Olr>));
    let counted = Arc::clone(&requests);
    let featured = Arc::clone(&advertised);
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
            if overload::supports_loss(&request) {
                featured.fetch_add(1, Ordering::SeqCst);
            }
            let Behaviour::Answer(code) = behaviour;
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
        Far {
            requests,
            advertised,
            report,
        },
    )
}

/// An S6a request as a client made it, advertising DOIC or not.
fn client_request(supports_doic: bool) -> DiameterMsg {
    let mut avps = vec![
        Avp::utf8(avp::SESSION_ID, 0, "mme.example.org;1;1"),
        Avp::utf8(avp::ORIGIN_HOST, 0, "mme.example.org"),
        Avp::utf8(avp::ORIGIN_REALM, 0, "example.org"),
        Avp::utf8(avp::DESTINATION_REALM, 0, "example.org"),
    ];
    if supports_doic {
        avps.push(overload::supported_features_avp(overload::FEATURE_LOSS));
    }
    DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code: 318,
        application_id: S6A,
        hop_by_hop: 0x1234,
        end_to_end: 0x5678,
        avps,
    }
}

async fn through(
    first: &Arc<DiameterClient>,
    alternates: &[Arc<DiameterClient>],
    supports_doic: bool,
) -> DiameterMsg {
    let policy = RetryPolicy::from_config(&agent_config());
    let mut request = client_request(supports_doic);
    relay(
        &policy,
        &mut request,
        Target {
            first,
            alternates,
            configured: 2,
        },
        Duration::from_secs(5),
        ("relay.example.org", "example.org"),
    )
    .await
}

fn agent_config() -> siphon::config::DiameterConfig {
    serde_saphyr::from_str("overload:\n  agent: true\n").expect("the configuration parses")
}

fn result_of(answer: &DiameterMsg) -> Option<u32> {
    answer.answer_result_codes().0
}

fn realm_report(answer: &DiameterMsg) -> Olr {
    overload::parse_olr(answer).expect("the answer carries an OC-OLR")
}

#[tokio::test]
async fn a_relay_that_is_an_agent_speaks_for_the_realm_and_diverts_what_a_backend_cannot_take() {
    overload::install(Overload::from_config(agent_config().overload.as_ref()));

    let (a, far_a) = far("a.example.org", Behaviour::Answer(2001), None).await;
    let (b, far_b) = far("b.example.org", Behaviour::Answer(2001), None).await;

    // Backend a reports 100 percent about itself, in an answer to a client
    // that supports DOIC: the client hears the realm's report, 50 percent of
    // two backends, and not the host report.
    *far_a.report.lock().expect("report") = Some(Olr {
        sequence: 1,
        report_type: ReportType::Host,
        validity_secs: 30,
        reduction_percentage: 100,
    });
    let answer = through(&a, &[Arc::clone(&b)], true).await;
    assert_eq!(result_of(&answer), Some(2001));
    assert_eq!(answer.hop_by_hop, 0x1234, "the client's identifiers");
    assert_eq!(answer.end_to_end, 0x5678);
    let first = realm_report(&answer);
    assert_eq!(first.report_type, ReportType::Realm);
    assert_eq!(first.reduction_percentage, 50);
    assert_eq!(answer.find_all(avp::OC_OLR, 0).count(), 1, "one report");
    assert!(overload::supports_loss(&answer));
    assert_eq!(far_a.advertised.load(Ordering::SeqCst), 1);

    // The next request for a is abated at the agent and goes to b. The report
    // still stands, with the same sequence number.
    let answer = through(&a, &[Arc::clone(&b)], true).await;
    assert_eq!(result_of(&answer), Some(2001));
    assert_eq!(far_a.requests.load(Ordering::SeqCst), 1, "a never saw it");
    assert_eq!(far_b.requests.load(Ordering::SeqCst), 1, "b took it");
    let second = realm_report(&answer);
    assert_eq!(second.sequence, first.sequence);
    assert_eq!(second.reduction_percentage, 50);

    // A client that does not support DOIC is not told: the backend still is
    // advertised to, on its behalf, and is the one asked.
    let answer = through(&a, &[Arc::clone(&b)], false).await;
    assert_eq!(result_of(&answer), Some(2001));
    assert!(overload::parse_olr(&answer).is_none());
    assert!(answer.find(avp::OC_SUPPORTED_FEATURES, 0).is_none());
    assert_eq!(
        far_b.advertised.load(Ordering::SeqCst),
        far_b.requests.load(Ordering::SeqCst),
        "every request b saw advertised DOIC"
    );

    // b reports 100 percent as well: nothing is left, and the client gets
    // 3004 from the agent, carrying the realm at 100 percent.
    *far_b.report.lock().expect("report") = Some(Olr {
        sequence: 1,
        report_type: ReportType::Host,
        validity_secs: 30,
        reduction_percentage: 100,
    });
    let answer = through(&b, &[], true).await;
    assert_eq!(
        result_of(&answer),
        Some(2001),
        "b took the request that told"
    );
    let served_by_a = far_a.requests.load(Ordering::SeqCst);
    let served_by_b = far_b.requests.load(Ordering::SeqCst);
    let answer = through(&a, &[Arc::clone(&b)], true).await;
    assert_eq!(result_of(&answer), Some(3004), "every backend abates it");
    assert!(answer.flags & codec::FLAG_ERROR != 0);
    let all = realm_report(&answer);
    assert_eq!(all.report_type, ReportType::Realm);
    assert_eq!(all.reduction_percentage, 100);
    assert!(all.sequence > first.sequence, "{first:?} {all:?}");
    assert_eq!(far_a.requests.load(Ordering::SeqCst), served_by_a);
    assert_eq!(far_b.requests.load(Ordering::SeqCst), served_by_b);

    // Without the agent a relay changes nothing: the host report passes
    // through, no OC-Supported-Features is added to the request.
    overload::install(Overload::new(false, None));
    let (c, far_c) = far("c.example.org", Behaviour::Answer(2001), None).await;
    *far_c.report.lock().expect("report") = Some(Olr {
        sequence: 1,
        report_type: ReportType::Host,
        validity_secs: 30,
        reduction_percentage: 30,
    });
    let answer = through(&c, &[], false).await;
    assert_eq!(far_c.advertised.load(Ordering::SeqCst), 0);
    let passed = overload::parse_olr(&answer).expect("the backend's own report");
    assert_eq!(passed.report_type, ReportType::Host);
    assert_eq!(passed.reduction_percentage, 30);
}
