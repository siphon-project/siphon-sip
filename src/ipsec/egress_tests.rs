//! A P-CSCF's TCP requests to UEs over the outbound pool (TS 24.229 clause
//! 5.2.2.2 1A b): each goes on a connection the P-CSCF opens from its one
//! protected client port to the UE's protected server port, reused for the
//! next request, with the UE's responses read off it into the inbound path;
//! and the connections drain to none once the UEs' pairs are deleted.
//!
//! Loopback stands in for the access network: the P-CSCF is 127.0.0.1, UE
//! `i` is 127.0.0.(20 + i) with a listener for its protected server port.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    pcscf_tcp_request_egress, EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager, SaProtocol,
    SaRole, SecurityAssociationPair,
};
use crate::config::TlsMethod;
use crate::transport::pool::{build_outbound_tls_config, ConnectionPool};
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport};

const PCSCF: &str = "127.0.0.1";
/// The P-CSCF's protected server port, where the UEs' own connections land.
const PORT_PS: u16 = 5066;
const UE_PORT_C: u16 = 6100;
const UES: u8 = 4;

fn ensure_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

/// A free port on 127.0.0.1 for the protected client port, released so the
/// pool can bind it (SO_REUSEADDR).
fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind((PCSCF, 0)).expect("a free port");
    socket.local_addr().expect("bound").port()
}

fn pcscf_ip() -> IpAddr {
    PCSCF.parse().expect("an address")
}

async fn install(
    manager: &IpsecManager,
    ue: IpAddr,
    ue_port_c: u16,
    ue_port_s: u16,
    port_pc: u16,
) -> SecurityAssociationPair {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    let sa = SecurityAssociationPair {
        ue_addr: ue,
        pcscf_addr: pcscf_ip(),
        ue_port_c,
        ue_port_s,
        pcscf_port_c: port_pc,
        pcscf_port_s: PORT_PS,
        spi_uc: 70_000 + u32::from(ue_port_c),
        spi_us: 80_000 + u32::from(ue_port_c),
        spi_pc,
        spi_ps,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: std::time::Instant::now(),
        created_at: std::time::Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    };
    manager.create_sa_pair(sa.clone()).await.expect("installed");
    sa
}

/// An MT request as the dispatcher hands it down: to the UE's client port,
/// on the UE's own connection, from the listener it arrived on.
fn mt_request(ue: IpAddr, call_id: &str) -> OutboundMessage {
    let data = format!(
        concat!(
            "OPTIONS sip:001010000000001@{ue} SIP/2.0\r\n",
            "Via: SIP/2.0/TCP {pcscf}:{port_ps};branch=z9hG4bK-{call_id}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ue = ue,
        pcscf = PCSCF,
        port_ps = PORT_PS,
        call_id = call_id,
    );
    OutboundMessage {
        connection_id: ConnectionId(9_000),
        transport: Transport::Tcp,
        destination: SocketAddr::new(ue, UE_PORT_C),
        data: Bytes::from(data),
        source_local_addr: Some(SocketAddr::new(pcscf_ip(), PORT_PS)),
        server_name: None,
        verify_server: None,
        followups: None,
    }
}

const ANSWER: &[u8] = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";

/// One UE: take the P-CSCF's connection, answer every request on it, and
/// report who connected.
async fn ue_server(
    listener: tokio::net::TcpListener,
    accepted: tokio::sync::mpsc::UnboundedSender<SocketAddr>,
) {
    while let Ok((mut stream, peer)) = listener.accept().await {
        let _ = accepted.send(peer);
        tokio::spawn(async move {
            let mut buffer = [0u8; 4096];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => {
                        // One answer per request in the read.
                        let requests = buffer[..read]
                            .windows(4)
                            .filter(|window| *window == b"\r\n\r\n")
                            .count();
                        for _ in 0..requests {
                            if stream.write_all(ANSWER).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        });
    }
}

async fn send(
    pool: &ConnectionPool,
    manager: &IpsecManager,
    message: OutboundMessage,
) -> ConnectionId {
    let moved = pcscf_tcp_request_egress(manager, PORT_PS, message);
    assert_eq!(moved.connection_id, ConnectionId::default());
    let source = moved
        .source_local_addr
        .expect("pinned to the protected client port");
    pool.send_tcp_from(source, moved.destination, moved.data)
        .await
        .expect("the P-CSCF's connection opens")
}

async fn answer(inbound: &flume::Receiver<InboundMessage>) -> InboundMessage {
    tokio::time::timeout(Duration::from_secs(5), inbound.recv_async())
        .await
        .expect("an answer within 5 s")
        .expect("the inbound channel is open")
}

#[tokio::test(flavor = "multi_thread")]
async fn p_cscf_requests_ride_its_own_connections_which_drain_with_the_pairs() {
    ensure_crypto_provider();
    let port_pc = free_port();
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let (inbound_tx, inbound) = flume::unbounded();
    let pool = ConnectionPool::new(
        Arc::new(DashMap::new()),
        inbound_tx,
        SocketAddr::new(pcscf_ip(), 5060),
        None,
        None,
        None,
        build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
    );

    let mut ues = Vec::new();
    for index in 0..UES {
        let ue: IpAddr = format!("127.0.0.{}", 20 + index)
            .parse()
            .expect("an address");
        let listener = tokio::net::TcpListener::bind((ue, 0))
            .await
            .expect("the UE's protected server port");
        let port_us = listener.local_addr().expect("bound").port();
        let (accepted_tx, accepted) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(ue_server(listener, accepted_tx));
        install(&manager, ue, UE_PORT_C, port_us, port_pc).await;
        ues.push((ue, port_us, accepted));
    }

    for (ue, port_us, accepted) in &mut ues {
        let first = send(&pool, &manager, mt_request(*ue, "first")).await;
        let peer = tokio::time::timeout(Duration::from_secs(5), accepted.recv())
            .await
            .expect("the UE accepts")
            .expect("a peer");
        assert_eq!(
            peer,
            SocketAddr::new(pcscf_ip(), port_pc),
            "opened from the P-CSCF's protected client port, the same for every UE"
        );
        let response = answer(&inbound).await;
        assert_eq!(response.connection_id, first);
        assert_eq!(response.remote_addr, SocketAddr::new(*ue, *port_us));
        assert_eq!(response.local_addr, SocketAddr::new(pcscf_ip(), port_pc));

        let second = send(&pool, &manager, mt_request(*ue, "second")).await;
        assert_eq!(second, first, "the next request reuses the connection");
        assert_eq!(answer(&inbound).await.connection_id, first);
        assert!(accepted.try_recv().is_err(), "no second connection");
    }
    assert_eq!(pool.active_connections(), usize::from(UES));

    // The binding goes, and its pair with it (the liveness reaper and the
    // expiry sweep delete directly): the P-CSCF's connection goes too.
    for (ue, _, _) in &ues {
        manager
            .delete_sa_pair(ue, UE_PORT_C)
            .await
            .expect("deleted");
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while pool.active_connections() > 0 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        pool.active_connections(),
        0,
        "every P-CSCF-opened connection drains with its pair"
    );
    for (ue, port_us, _) in &ues {
        assert!(
            crate::transport::disconnect::peer_closed_within(
                SocketAddr::new(*ue, *port_us),
                Duration::from_secs(1)
            )
            .await,
            "no live connection left to {ue}"
        );
    }
    assert_eq!(manager.active_count(), 0);
}

/// A re-registration's new pair keeps the protected server port (TS 33.203
/// clause 7.4.0), so deleting the old pair leaves the connection to it to
/// the new one.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_superseded_pair_keeps_the_connection_the_new_one_shares() {
    ensure_crypto_provider();
    let port_pc = free_port();
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let (inbound_tx, inbound) = flume::unbounded();
    let pool = ConnectionPool::new(
        Arc::new(DashMap::new()),
        inbound_tx,
        SocketAddr::new(pcscf_ip(), 5060),
        None,
        None,
        None,
        build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
    );
    let ue: IpAddr = "127.0.0.40".parse().expect("an address");
    let listener = tokio::net::TcpListener::bind((ue, 0))
        .await
        .expect("the UE's protected server port");
    let port_us = listener.local_addr().expect("bound").port();
    let (accepted_tx, _accepted) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(ue_server(listener, accepted_tx));
    install(&manager, ue, UE_PORT_C, port_us, port_pc).await;
    let connection = send(&pool, &manager, mt_request(ue, "old")).await;
    answer(&inbound).await;

    // The new pair: another client port, the same server port.
    let renewed = install(&manager, ue, UE_PORT_C + 2, port_us, port_pc).await;
    manager
        .delete_sa_pair(&ue, UE_PORT_C)
        .await
        .expect("deleted");

    let mut request = mt_request(ue, "new");
    request.destination = SocketAddr::new(ue, renewed.ue_port_c);
    assert_eq!(send(&pool, &manager, request).await, connection);
    assert_eq!(answer(&inbound).await.connection_id, connection);
}
