//! The over-MTU UDP-to-TCP switch (RFC 3261 §18.1.1) for a request siphon
//! originates as a UAC: `proxy.send_request`, the NOTIFYs and SUBSCRIBEs of
//! `proxy.subscribe_state`, `presence.notify`.
//!
//! The decision is the relay's ([`super::mtu_tcp_upgrade`], and
//! [`super::over_mtu`] toward a UE with a security association): the same
//! threshold, the same probe of the next hop, the same negative cache and the
//! same log lines. Only the waits differ. Those senders are futures on the
//! runtime, so the probe's lookup and connect are awaited here instead of
//! blocking a worker.

use super::over_mtu::{protected_plan, ProtectedOverMtu};
use super::*;

/// What the decision reads, from the UAC sender that originates the request.
pub(crate) struct OriginatedOverMtu<'a> {
    /// `listen.mtu`.
    pub(crate) mtu: u16,
    /// The outbound pool, which opens a P-CSCF's connection to a UE's
    /// protected server port.
    pub(crate) pool: &'a ConnectionPool,
    /// The security associations of a P-CSCF, when this node is one.
    pub(crate) ipsec: Option<&'a crate::ipsec::IpsecManager>,
    pub(crate) resolver: &'a SipResolver,
}

/// Where a request moved to TCP goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OriginatedTcp {
    /// The address to send to over TCP.
    pub(crate) destination: SocketAddr,
    /// Over a UE's security association: `destination` is the address the UDP
    /// request had, and the egress puts the request on the P-CSCF's connection
    /// to the UE's protected server port (TS 24.229 clause 5.2.2.2 1A b),
    /// which is open by now.
    pub(crate) protected: bool,
}

impl OriginatedOverMtu<'_> {
    /// The TCP path of a request of `serialized_len` bytes that would leave
    /// over UDP for `destination`: `Some` once a TCP path there is known to be
    /// up, `None` to send it over UDP as it is (not over the threshold, or no
    /// reachable TCP path, which is logged once per window).
    ///
    /// `target` is what `destination` was resolved from, a SIP URI or a bare
    /// `ip:port`, and names the host that is probed.
    pub(crate) async fn upgrade(
        &self,
        serialized_len: usize,
        target: &str,
        destination: SocketAddr,
    ) -> Option<OriginatedTcp> {
        let mtu = Some(self.mtu);
        match protected_plan(mtu, self.ipsec, Transport::Udp, serialized_len, destination) {
            Ok(connect) => {
                let opened = self.pool.connect_tcp_from(connect.local, connect.tcp).await;
                return match connect.conclude(opened) {
                    ProtectedOverMtu::Tcp { .. } => Some(OriginatedTcp {
                        destination,
                        protected: true,
                    }),
                    ProtectedOverMtu::NotProtected | ProtectedOverMtu::KeepUdp => None,
                };
            }
            Err(ProtectedOverMtu::NotProtected) => {}
            Err(ProtectedOverMtu::KeepUdp | ProtectedOverMtu::Tcp { .. }) => return None,
        }
        let probe = TcpProbe::claim(mtu, Transport::Udp, serialized_len, destination)?;
        let path = reachable_tcp_path(target, destination, self.resolver).await;
        probe.conclude(path).map(|(_, destination)| OriginatedTcp {
            destination,
            protected: false,
        })
    }
}

/// [`resolve_tcp_path`], awaited: the candidate address is chosen the same way
/// ([`tcp_candidate`]) and a connect inside [`TCP_PROBE_TIMEOUT`] is the
/// reachability test.
async fn reachable_tcp_path(
    target: &str,
    udp_destination: SocketAddr,
    resolver: &SipResolver,
) -> Option<SocketAddr> {
    let candidate = match tcp_candidate(target)? {
        TcpCandidate::SameAddress => udp_destination,
        TcpCandidate::Lookup(uri) => {
            resolver
                .resolve(&uri.host, uri.port, uri.scheme.as_str(), Some("tcp"))
                .await
                .into_iter()
                .next()?
                .address
        }
    };
    let connected =
        tokio::time::timeout(TCP_PROBE_TIMEOUT, tokio::net::TcpStream::connect(candidate)).await;
    matches!(connected, Ok(Ok(_))).then_some(candidate)
}

/// Forget what the probe cache holds for `next_hop`, for a test outside the
/// dispatcher whose loopback port another test may have seen refuse within
/// the window.
#[cfg(test)]
pub(crate) fn forget_tcp_probe(next_hop: SocketAddr) {
    probe_cache().forget(next_hop);
}

#[cfg(test)]
#[path = "originated_tests.rs"]
mod tests;
