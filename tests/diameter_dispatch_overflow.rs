//! A burst of requests on one connection against a slow consumer: every
//! request is answered, with the result or with 3004 and an OC-OLR, and none
//! is left to time out.

#![allow(clippy::disallowed_methods)] // test runtime may block

use siphon::diameter::codec::{Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
use siphon::diameter::dictionary::{self, avp};
use siphon::diameter::forward;
use siphon::diameter::lifecycle::PeerLifecycle;
use siphon::diameter::overload::{self, Overload};
use siphon::diameter::peer::{self, PeerConfig};
use siphon::diameter::transport::DiameterStream;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

const S6A: u32 = dictionary::S6A_APP_ID;
const BURST: usize = 300;

fn config(origin_host: &str, port: u16) -> PeerConfig {
    PeerConfig {
        host: "127.0.0.1".to_string(),
        port,
        origin_host: origin_host.to_string(),
        origin_realm: "example.net".to_string(),
        destination_host: None,
        destination_realm: "example.net".to_string(),
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

fn request(client: &peer::DiameterPeer, advertise_doic: bool) -> Vec<u8> {
    let mut avps = vec![
        Avp::utf8(avp::SESSION_ID, 0, "client.example.net;1;1"),
        Avp::utf8(avp::ORIGIN_HOST, 0, "client.example.net"),
        Avp::utf8(avp::ORIGIN_REALM, 0, "example.net"),
        Avp::utf8(avp::DESTINATION_REALM, 0, "example.net"),
    ];
    if advertise_doic {
        avps.push(overload::supported_features_avp(overload::FEATURE_LOSS));
    }
    DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code: 318,
        application_id: S6A,
        hop_by_hop: client.next_hbh(),
        end_to_end: client.next_e2e(),
        avps,
    }
    .to_wire()
}

#[tokio::test]
async fn a_burst_on_one_connection_is_answered_in_full_never_dropped() {
    // The node reports overload; the client does not abate.
    let reporting: siphon::config::DiameterConfig =
        serde_saphyr::from_str("overload:\n  reporting: {validity: 30}\n").expect("config");
    overload::install(Overload::from_config(reporting.overload.as_ref()));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        peer::accept(
            DiameterStream::from(stream),
            config("server.example.net", 0),
        )
        .await
        .expect("the capabilities exchange completes")
    });
    let (client, _client_incoming) = peer::connect(config("client.example.net", port))
        .await
        .expect("dial");
    let (server_peer, mut incoming) = server.await.expect("accepted");

    // A slow handler: one request at a time, 20 ms each.
    let answering = Arc::clone(&server_peer);
    tokio::spawn(async move {
        while let Some(received) = incoming.recv().await {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let request = DiameterMsg::from_wire(&received.raw).expect("parses");
            let answer =
                forward::build_answer(&request, "server.example.net", "example.net", 2001, None);
            let _ = answering.send_response(answer.to_wire()).await;
        }
    });

    let mut sends = Vec::new();
    for _ in 0..BURST {
        let wire = request(&client, true);
        let client = Arc::clone(&client);
        sends.push(tokio::spawn(async move {
            client
                .send_request_timeout(wire, Duration::from_secs(4))
                .await
        }));
    }
    let (mut served, mut busy, mut silent) = (0, 0, 0);
    for send in sends {
        match send.await.expect("task") {
            Ok(answer) => {
                let message = DiameterMsg::from_wire(&answer.raw).expect("parses");
                match message.answer_result_codes().0 {
                    Some(2001) => served += 1,
                    Some(3004) => {
                        busy += 1;
                        let report = overload::parse_olr(&message)
                            .expect("a 3004 comes with an OC-OLR for a DOIC client");
                        assert!(report.reduction_percentage > 0);
                    }
                    other => panic!("unexpected result {other:?}"),
                }
            }
            Err(error) => {
                assert!(error.contains("timed out"), "{error}");
                silent += 1;
            }
        }
    }
    overload::install(Overload::new(false, None));
    eprintln!("served {served}, busy {busy}, silent {silent}");
    assert_eq!(silent, 0, "{silent} of {BURST} requests got no answer");
    assert_eq!(served + busy, BURST);
    assert!(served > 0 && busy > 0, "served {served}, busy {busy}");
}

#[tokio::test]
async fn a_request_for_a_connection_nothing_serves_is_answered_3002() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("address").port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        peer::accept(
            DiameterStream::from(stream),
            config("server.example.net", 0),
        )
        .await
        .expect("the capabilities exchange completes")
    });
    let (client, _client_incoming) = peer::connect(config("client.example.net", port))
        .await
        .expect("dial");
    let (_server_peer, incoming) = server.await.expect("accepted");
    // The consumer is gone, as at shutdown.
    drop(incoming);
    let answer = client
        .send_request_timeout(request(&client, false), Duration::from_secs(4))
        .await
        .expect("answered, not timed out");
    let message = DiameterMsg::from_wire(&answer.raw).expect("parses");
    assert_eq!(message.answer_result_codes().0, Some(3002));
}
