//! DOIC (RFC 7683) over real loopback connections: the node as a reacting
//! node, as a relay and as a reporting node. A process of its own, because
//! the overload behaviour is installed process-wide. The far end is a raw
//! socket that decodes what the node writes with the lossless tree, an
//! independent reader of the bytes.

#![allow(clippy::disallowed_methods)] // test runtime may block

use siphon::diameter::codec::{self, Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
use siphon::diameter::dictionary::{self, avp};
use siphon::diameter::forward;
use siphon::diameter::lifecycle::PeerLifecycle;
use siphon::diameter::overload::{self, Olr, Overload, ReportType, ReportingState, FEATURE_LOSS};
use siphon::diameter::peer::{self, PeerConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const S6A: u32 = dictionary::S6A_APP_ID;

fn config(origin_host: &str) -> PeerConfig {
    PeerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
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

fn air(peer: &peer::DiameterPeer) -> Vec<u8> {
    DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code: dictionary::CMD_AUTHENTICATION_INFORMATION,
        application_id: S6A,
        hop_by_hop: peer.next_hbh(),
        end_to_end: peer.next_e2e(),
        avps: vec![
            Avp::utf8(avp::SESSION_ID, 0, "node.example.org;1;1"),
            Avp::utf8(avp::ORIGIN_HOST, 0, "node.example.org"),
            Avp::utf8(avp::ORIGIN_REALM, 0, "example.org"),
            Avp::utf8(avp::DESTINATION_REALM, 0, "example.org"),
        ],
    }
    .to_wire()
}

/// What the far end saw and what it will add to its next answer.
#[derive(Default)]
struct FarEnd {
    /// Whether each request carried the loss feature, in arrival order.
    advertised: Vec<bool>,
    /// An OC-OLR for the next answer.
    next_report: Option<Olr>,
}

/// A raw far end named `hss.example.org` that answers every request with
/// 2001, plus the report it is told to add.
async fn far_end(state: Arc<Mutex<FarEnd>>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut reader = tokio::io::BufReader::new(&mut stream);
        let cer = codec::read_diameter_message(&mut reader)
            .await
            .expect("CER");
        let cer = DiameterMsg::from_wire(&cer).expect("CER decodes");
        let cea = peer::build_cea(
            &config("hss.example.org"),
            dictionary::DIAMETER_SUCCESS,
            cer.hop_by_hop,
            cer.end_to_end,
        );
        drop(reader);
        stream.write_all(&cea).await.expect("CEA");
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = tokio::io::BufReader::new(read_half);
        while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
            let Ok(request) = DiameterMsg::from_wire(&bytes) else {
                break;
            };
            let mut answer = forward::build_answer(
                &request,
                "hss.example.org",
                "example.org",
                dictionary::DIAMETER_SUCCESS,
                None,
            );
            if request.application_id != 0 {
                let mut state = state.lock().expect("state");
                state.advertised.push(overload::supports_loss(&request));
                if let Some(report) = state.next_report.take() {
                    answer.avps.push(overload::olr_avp(&report));
                }
            }
            if write_half.write_all(&answer.to_wire()).await.is_err() {
                break;
            }
        }
    });
    (port, task)
}

async fn send(peer: &peer::DiameterPeer) -> Result<(), String> {
    peer.send_request_timeout(air(peer), Duration::from_secs(5))
        .await
        .map(|_| ())
}

/// Requests sent until `count` have been tried; how many were abated.
async fn abated_of(peer: &peer::DiameterPeer, count: usize) -> usize {
    let mut abated = 0;
    for _ in 0..count {
        match send(peer).await {
            Ok(()) => {}
            Err(error) if overload::is_abated(&error) => abated += 1,
            Err(error) => panic!("unexpected failure: {error}"),
        }
    }
    abated
}

#[tokio::test]
async fn the_node_as_a_reacting_node_a_relay_and_a_reporting_node() {
    overload::install(Overload::new(true, Some(ReportingState::new(30, None))));

    // ── Reacting node ───────────────────────────────────────────────────
    let state = Arc::new(Mutex::new(FarEnd::default()));
    let (port, _far) = far_end(Arc::clone(&state)).await;
    let mut dial = config("node.example.org");
    dial.port = port;
    let (node, _incoming) = peer::connect(dial).await.expect("dial");
    assert_eq!(node.remote_origin_host(), Some("hss.example.org"));

    // It advertises DOIC in a request it originates, and no report is in
    // force yet: nothing is abated.
    send(&node)
        .await
        .expect("an unreported peer takes requests");
    assert_eq!(state.lock().expect("state").advertised, vec![true]);

    // The far end reports 50 %.
    state.lock().expect("state").next_report = Some(Olr {
        sequence: 1,
        report_type: ReportType::Host,
        validity_secs: 30,
        reduction_percentage: 50,
    });
    send(&node)
        .await
        .expect("the answer that carries the report");
    let total = 4000;
    let abated = abated_of(&node, total).await;
    let share = abated as f64 / total as f64 * 100.0;
    assert!(
        (share - 50.0).abs() < 4.0,
        "abated {share:.1} % of {total} under a 50 % report"
    );

    // A newer sequence number that says 0 ends it. The report reaches the
    // node on the answer to a request that was let through.
    state.lock().expect("state").next_report = Some(Olr {
        sequence: 2,
        report_type: ReportType::Host,
        validity_secs: 30,
        reduction_percentage: 0,
    });
    let mut delivered = false;
    for _ in 0..200 {
        if send(&node).await.is_ok() && state.lock().expect("state").next_report.is_none() {
            delivered = true;
            break;
        }
    }
    assert!(delivered, "the 0 % report reached the node");
    assert_eq!(
        abated_of(&node, 500).await,
        0,
        "nothing is abated after a 0 % report"
    );

    // A report abates until its validity runs out: 100 % for one second.
    state.lock().expect("state").next_report = Some(Olr {
        sequence: 3,
        report_type: ReportType::Host,
        validity_secs: 1,
        reduction_percentage: 100,
    });
    send(&node)
        .await
        .expect("the answer that carries the report");
    assert_eq!(
        abated_of(&node, 50).await,
        50,
        "everything is abated while it holds"
    );
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(
        abated_of(&node, 50).await,
        0,
        "and nothing once its validity ran out"
    );

    // ── Relay: what it is given is what it sends ────────────────────────
    let before = state.lock().expect("state").advertised.len();
    node.send_relayed_timeout(air(&node), Duration::from_secs(5))
        .await
        .expect("relayed");
    let mut with_feature = DiameterMsg::from_wire(&air(&node)).expect("decodes");
    with_feature
        .avps
        .push(overload::supported_features_avp(0x8));
    node.send_relayed_timeout(with_feature.to_wire(), Duration::from_secs(5))
        .await
        .expect("relayed");
    let seen = state.lock().expect("state").advertised.clone();
    assert_eq!(
        &seen[before..],
        &[false, false],
        "a relayed request gains no loss feature and keeps the one it had"
    );

    // ── Reporting node ──────────────────────────────────────────────────
    let reporting = overload::current();
    let reporting = reporting.reporting.as_ref().expect("reporting installed");
    reporting.set(0, None, std::time::Instant::now());
    let request = |features: Option<u64>| {
        let mut message = DiameterMsg::from_wire(&air(&node)).expect("decodes");
        message
            .avps
            .push(Avp::utf8(avp::ORIGIN_HOST, 0, "mme.example.org"));
        if let Some(vector) = features {
            message.avps.push(overload::supported_features_avp(vector));
        }
        message.to_wire()
    };
    let answer_to = |wire: &[u8]| {
        let request = DiameterMsg::from_wire(wire).expect("decodes");
        forward::build_answer(&request, "node.example.org", "example.org", 2001, None).to_wire()
    };
    let capable = request(Some(FEATURE_LOSS));
    let capable_features = overload::request_features(&capable);
    assert_eq!(capable_features & FEATURE_LOSS, FEATURE_LOSS);
    let legacy = request(None);
    assert_eq!(overload::request_features(&legacy), 0);

    // No overload: a capable requester is told DOIC is supported, no OLR.
    let calm = DiameterMsg::from_wire(&overload::annotate_answer(
        capable_features,
        answer_to(&capable),
    ))
    .expect("decodes");
    assert!(overload::supports_loss(&calm));
    assert!(overload::parse_olr(&calm).is_none());

    // Overload: the capable requester gets the report, the legacy one none.
    reporting.set(35, None, std::time::Instant::now());
    let loaded = DiameterMsg::from_wire(&overload::annotate_answer(
        capable_features,
        answer_to(&capable),
    ))
    .expect("decodes");
    assert_eq!(
        overload::parse_olr(&loaded).map(|olr| olr.reduction_percentage),
        Some(35)
    );
    let plain_wire = answer_to(&legacy);
    assert_eq!(
        overload::annotate_answer(overload::request_features(&legacy), plain_wire.clone()),
        plain_wire,
        "a requester that did not advertise DOIC gets the answer as it was"
    );
    let _ = TcpStream::connect(("127.0.0.1", port)).await;
}
