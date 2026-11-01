//! Test support for the over-MTU switch of a request over a registrant UE's SA
//! flow: a P-CSCF protected server port that listens for TCP (or does not) on
//! loopback, a UE protected client port on an address of its own on
//! 127.0.0.0/8, and the `registration.flow()` between them.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use super::flow_kind::{FlowKind, RegistrantFlow};
use super::registrar::PyFlow;
use crate::transport::pool::ConnectionPool;

pub(crate) struct UeLab {
    /// The P-CSCF's protected server port, listening for TCP when asked to.
    pub(crate) listener: Option<tokio::net::TcpListener>,
    pub(crate) pcscf: SocketAddr,
    pub(crate) ue_ip: IpAddr,
    /// The UE's protected client port: the source of its connection.
    pub(crate) source: SocketAddr,
    /// The UE's protected server port, the Via sent-by.
    pub(crate) server: SocketAddr,
}

impl UeLab {
    /// A UE on `127.0.0.<octet>` with the registrant fixtures' protected ports
    /// (6100, 6101), its P-CSCF listening for TCP when `tcp`. Every test takes
    /// an octet of its own.
    pub(crate) async fn new(octet: u8, tcp: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a P-CSCF port");
        let pcscf = listener.local_addr().expect("its address");
        let ue_ip: IpAddr = format!("127.0.0.{octet}").parse().expect("an address");
        // The client and server ports of the registrant fixtures, on an
        // address of the UE's own.
        let source = SocketAddr::new(ue_ip, 6100);
        let server = SocketAddr::new(ue_ip, 6101);
        Self {
            listener: tcp.then_some(listener),
            pcscf,
            ue_ip,
            source,
            server,
        }
    }

    /// The fixtures' UE registered through this P-CSCF over an established SA
    /// set: its AoR, with the set's client port the lab's `source`.
    pub(crate) fn established(
        &self,
        manager: &crate::registrant::RegistrantManager,
        index: u32,
    ) -> String {
        use crate::registrant::test_support;
        let mut entry = test_support::ue(index, Some(self.ue_ip));
        entry.destination = self.pcscf;
        manager.try_add(entry).expect("added");
        let aor = test_support::impu(index);
        crate::registrant::rotate_sa_set_against(
            manager,
            &aor,
            &format!(
                "ipsec-3gpp; alg=hmac-sha-1-96; ealg=null; spi-c=55555; spi-s=66666; \
                 port-c=5064; port-s={}",
                self.pcscf.port()
            ),
        );
        aor
    }

    /// `registration.flow()`: UDP, from the client port to the P-CSCF's server
    /// port.
    pub(crate) fn flow(&self) -> PyFlow {
        PyFlow {
            transport: "udp".to_string(),
            source_addr: self.pcscf,
            local_addr: self.source,
            connection_id: 0,
            kind: FlowKind::Outbound(RegistrantFlow {
                aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org".to_string(),
                sent_by: self.server,
            }),
        }
    }

    /// The same endpoints as a callee's flow, which never switches.
    pub(crate) fn inbound_flow(&self) -> PyFlow {
        PyFlow {
            kind: FlowKind::Inbound,
            ..self.flow()
        }
    }

    /// Let `pool` bind the client port, as the registration loop does for a
    /// held SA set.
    pub(crate) fn pin(&self, pool: &ConnectionPool) {
        let sources: HashSet<SocketAddr> = [self.source].into();
        pool.reconcile_pinned_sources(sources.clone(), &sources);
    }

    /// The P-CSCF accepts the UE's connection and reports where it came from.
    pub(crate) async fn accept(&self) -> (tokio::net::TcpStream, SocketAddr) {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.listener.as_ref().expect("a listening P-CSCF").accept(),
        )
        .await
        .expect("the UE connects")
        .expect("accepted")
    }

    /// Whether the P-CSCF sees a connection within a moment.
    pub(crate) async fn sees_connection(&self) -> bool {
        match &self.listener {
            Some(listener) => {
                tokio::time::timeout(std::time::Duration::from_millis(300), listener.accept())
                    .await
                    .is_ok()
            }
            None => false,
        }
    }
}

/// A body of `length` filler bytes.
pub(crate) fn filler(length: usize) -> Vec<u8> {
    vec![b'x'; length]
}
