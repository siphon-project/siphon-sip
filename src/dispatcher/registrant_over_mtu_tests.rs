//! A REGISTER over an IMS UE's SA set that is over the MTU goes over TCP on
//! that set (RFC 3261 clause 18.1.1; TS 33.203 clause 7.1, the SAs carry TCP and
//! UDP; TS 24.229 clause 5.1.1.2.2 1 b, the UE's connection leaves from its
//! protected client port to the P-CSCF's protected server port). This is the
//! authenticated REGISTER a challenge makes, on the temporary set the
//! dispatcher installs for it; the refresh loop's own is tested with the loop
//! (`registrant::refresh_tests`).
//!
//! The P-CSCF here is a real TCP listener on loopback and the UE is an address
//! of its own on 127.0.0.0/8, so the connect leaves from the protected client
//! port for real; the kernel SAs are the mock.

use super::protected_tests::{ip, wait_for, Harness};
use super::*;
use crate::registrant::register_extras::RegisterExtras;
use crate::registrant::test_support::{self, impu, ue};
use crate::transport::OutboundMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

const UE_ADDR: &str = "127.0.0.77";

/// The 401 of a P-CSCF whose protected server port is `port_s`.
fn challenge_extra(sqn: u64, port_s: u16) -> String {
    let challenge = test_support::aka_challenge_value(&format!("{sqn:012x}"));
    format!(
        "WWW-Authenticate: {challenge}\r\nSecurity-Server: ipsec-3gpp; alg=hmac-sha-1-96; \
         ealg=null; spi-c=70002; spi-s=70003; port-c=5064; port-s={port_s}\r\n"
    )
}

/// A harness whose router captures what is sent per transport, with an MTU of
/// 1280 and one UE (`body_len` bytes of REGISTER body) registering through
/// `pcscf`.
struct OverMtu {
    harness: Harness,
    udp: flume::Receiver<OutboundMessage>,
    tcp: flume::Receiver<OutboundMessage>,
}

fn over_mtu_harness(pcscf: SocketAddr, body_len: usize) -> OverMtu {
    let mut harness = Harness::new();
    harness.dispatcher.state.mtu = Some(1280);
    let (udp_tx, udp) = flume::unbounded();
    let (tcp_tx, tcp) = flume::unbounded();
    harness.dispatcher.state.outbound = Arc::new(crate::transport::OutboundRouter {
        udp: udp_tx.into(),
        udp_by_local: HashMap::new(),
        udp_dynamic: None,
        tcp: tcp_tx,
        tls: flume::unbounded().0,
        ws: flume::unbounded().0,
        wss: flume::unbounded().0,
        sctp: None,
    });
    let mut entry = ue(1, Some(ip(UE_ADDR)));
    entry.destination = pcscf;
    if body_len > 0 {
        entry = entry.with_register_extras(
            RegisterExtras::new(
                Some(("text/plain".to_string(), vec![b'x'; body_len])),
                Vec::new(),
            )
            .expect("extras"),
        );
    }
    harness.registrant.try_add(entry).expect("added");
    OverMtu { harness, udp, tcp }
}

impl OverMtu {
    /// The initial REGISTER, then the 401 with the P-CSCF's `port_s`.
    fn challenge(&mut self, port_s: u16) {
        let aor = impu(1);
        let built = self.harness.register(&aor);
        let call_id = self.harness.call_id(&built);
        self.harness
            .answer("401 Unauthorized", &call_id, &challenge_extra(1, port_s));
    }
}

async fn received(channel: &flume::Receiver<OutboundMessage>) -> OutboundMessage {
    tokio::time::timeout(Duration::from_secs(3), channel.recv_async())
        .await
        .expect("sent in time")
        .expect("channel open")
}

fn via(message: &OutboundMessage) -> String {
    String::from_utf8_lossy(&message.data)
        .lines()
        .find(|line| line.starts_with("Via:"))
        .unwrap_or_default()
        .to_string()
}

/// Over the threshold: the REGISTER leaves over TCP, from the UE's protected
/// client port to the P-CSCF's protected server port, its Via says TCP and
/// names the protected server port.
///
/// Before: it went out over UDP whatever its size, fragmented.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_mtu_authenticated_register_goes_over_tcp_on_its_sa_set() {
    let pcscf = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a P-CSCF");
    let pcscf_address = pcscf.local_addr().expect("its address");
    let mut over = over_mtu_harness(pcscf_address, 1500);
    over.challenge(pcscf_address.port());

    // The connection from the protected client port, carried by the set the
    // dispatcher installed before connecting.
    let (_connection, peer) = tokio::time::timeout(Duration::from_secs(3), pcscf.accept())
        .await
        .expect("the UE connects")
        .expect("accepted");
    assert_eq!(peer, SocketAddr::new(ip(UE_ADDR), 6100));
    assert_eq!(over.harness.ports(UE_ADDR), vec![6100], "the set is in");

    let register = received(&over.tcp).await;
    assert_eq!(register.transport, Transport::Tcp);
    assert_eq!(register.destination, pcscf_address);
    assert_eq!(
        register.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6100))
    );
    let text = String::from_utf8_lossy(&register.data);
    assert!(text.starts_with("REGISTER "), "{text}");
    assert!(
        via(&register).starts_with(&format!(
            "Via: SIP/2.0/TCP {UE_ADDR}:6101;branch=z9hG4bK-reg-"
        )),
        "{}",
        via(&register)
    );
    assert!(register.data.len() > 1500, "the body is in");
    assert!(
        over.udp.try_recv().is_err(),
        "nothing went over UDP as well"
    );
}

/// Under the threshold, or with no MTU configured, it stays UDP, from the same
/// protected client port, and no connection is opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_under_threshold_register_stays_udp_and_opens_no_connection() {
    // The authenticated REGISTER alone is about a kilobyte (AKA response,
    // Security-Client and -Verify): an MTU of 1600 puts the threshold at 1400.
    for (body_len, mtu) in [(0usize, Some(1600u16)), (1500, None)] {
        let pcscf = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a P-CSCF");
        let pcscf_address = pcscf.local_addr().expect("its address");
        let mut over = over_mtu_harness(pcscf_address, body_len);
        over.harness.dispatcher.state.mtu = mtu;
        over.challenge(pcscf_address.port());

        let register = received(&over.udp).await;
        assert_eq!(register.transport, Transport::Udp);
        assert_eq!(
            register.source_local_addr,
            Some(SocketAddr::new(ip(UE_ADDR), 6100))
        );
        assert!(
            via(&register).starts_with("Via: SIP/2.0/UDP "),
            "{register:?}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), pcscf.accept())
                .await
                .is_err(),
            "body {body_len}, mtu {mtu:?}: no TCP connection"
        );
        assert!(over.tcp.try_recv().is_err());
    }
}

/// A P-CSCF with no TCP on its protected server port refuses the connection:
/// RFC 3261 clause 18.1.1, the request is retried over UDP. It is not lost, the
/// entry does not fail, and the Via says UDP again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_connection_falls_back_to_udp() {
    // A port nothing listens on for TCP.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port");
    let mut over = over_mtu_harness(closed, 1500);
    over.challenge(closed.port());

    let register = received(&over.udp).await;
    assert_eq!(register.transport, Transport::Udp);
    assert_eq!(register.destination, closed);
    assert!(
        via(&register).starts_with("Via: SIP/2.0/UDP "),
        "{}",
        via(&register)
    );
    assert!(register.data.len() > 1500);
    assert!(over.tcp.try_recv().is_err());
    // Still registering, not failed.
    wait_for(|| {
        (over.harness.registrant.state(&impu(1))
            == Some(crate::registrant::RegistrantState::Challenging))
        .then_some(())
    })
    .await;
}
