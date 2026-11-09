//! Graceful Diameter shutdown over real loopback connections: what the far
//! end of every connection of this node sees when the node goes
//! (RFC 6733 section 5.4). A process of its own, so disconnecting "all" does
//! not reach connections another test holds. The far ends are raw sockets, an
//! independent peer that reads the bytes this node writes.

#![allow(clippy::disallowed_methods)] // test runtime may block

use siphon::diameter::codec::{self, DiameterMsg};
use siphon::diameter::dictionary;
use siphon::diameter::lifecycle::{disconnect_all, DisconnectCause};
use siphon::diameter::peer::{self, PeerConfig};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

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
        lifecycle: Default::default(),
        product_name: "SIPhon".to_string(),
        firmware_revision: 1,
    }
}

/// Read one message from a raw far end.
async fn read_tree(stream: &mut TcpStream) -> DiameterMsg {
    let bytes = tokio::time::timeout(Duration::from_secs(5), codec::read_diameter_message(stream))
        .await
        .expect("a message within the bound")
        .expect("a readable message");
    DiameterMsg::from_wire(&bytes).expect("a well-formed message")
}

/// Answer the DPR a raw far end receives and report its Disconnect-Cause,
/// then check the node closes its end after the answer.
async fn answer_dpr(mut stream: TcpStream) -> Option<u32> {
    let dpr = read_tree(&mut stream).await;
    assert!(dpr.is_request());
    assert_eq!(dpr.command_code, dictionary::CMD_DISCONNECT_PEER);
    let cause = dpr
        .find(dictionary::avp::DISCONNECT_CAUSE, 0)
        .and_then(|avp| avp.as_u32());
    let dpa = peer::build_dpa(
        "far.example.org",
        "example.org",
        dpr.hop_by_hop,
        dpr.end_to_end,
    );
    stream.write_all(&dpa).await.expect("DPA written");
    let closed = tokio::time::timeout(
        Duration::from_secs(5),
        codec::read_diameter_message(&mut stream),
    )
    .await
    .expect("the node closes its end after the DPA");
    assert!(closed.is_err(), "nothing follows the DPA, only the close");
    cause
}

#[tokio::test]
async fn shutdown_sends_a_dpr_with_rebooting_on_every_connection_and_waits_for_the_dpa() {
    // A connection this node dialled: the far end answers the CER.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let mut dial_config = config("node.example.org");
    dial_config.port = listener.local_addr().expect("address").port();
    let dialled_far = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let cer = read_tree(&mut stream).await;
        let cea = peer::build_cea(
            &config("far-a.example.org"),
            dictionary::DIAMETER_SUCCESS,
            cer.hop_by_hop,
            cer.end_to_end,
        );
        stream.write_all(&cea).await.expect("CEA written");
        stream
    });
    let (dialled, _dialled_incoming) = peer::connect(dial_config).await.expect("dial");
    let dialled_far = dialled_far.await.expect("far end task");

    // A connection that dialled this node: the far end sends the CER.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let node_port = listener.local_addr().expect("address").port();
    let accepted = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        peer::accept(stream.into(), config("node.example.org"))
            .await
            .expect("accept handshake")
    });
    let mut accepted_far = TcpStream::connect(("127.0.0.1", node_port))
        .await
        .expect("connect");
    accepted_far
        .write_all(&peer::build_cer(&config("far-b.example.org"), 1, 1))
        .await
        .expect("CER written");
    let cea = read_tree(&mut accepted_far).await;
    assert_eq!(cea.command_code, dictionary::CMD_CAPABILITIES_EXCHANGE);
    let (accepted_peer, _accepted_incoming) = accepted.await.expect("accept task");

    let seen_dialled = tokio::spawn(answer_dpr(dialled_far));
    let seen_accepted = tokio::spawn(answer_dpr(accepted_far));

    let summary = tokio::time::timeout(
        Duration::from_secs(5),
        disconnect_all(DisconnectCause::Rebooting),
    )
    .await
    .expect("shutdown is bounded");

    assert_eq!(
        summary.answered, 2,
        "both connections were answered: {summary:?}"
    );
    assert_eq!(summary.unanswered, 0);
    assert_eq!(seen_dialled.await.expect("task"), Some(0), "REBOOTING");
    assert_eq!(seen_accepted.await.expect("task"), Some(0), "REBOOTING");
    assert!(!dialled.is_open());
    assert!(!accepted_peer.is_open());
}
