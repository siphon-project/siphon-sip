//! The over-MTU UDP-to-TCP switch (RFC 3261 §18.1.1) toward a UE that has a
//! security association with this P-CSCF.
//!
//! The generic switch ([`super::mtu_tcp_upgrade`]) probes TCP at the UDP
//! destination with an unbound connect. Toward a protected UE that destination
//! is the UE's protected client port, where nothing listens for TCP, and the
//! probe leaves from an ephemeral port no association carries, so it always
//! failed and every large request (a reg-event NOTIFY with a few contacts in
//! it) went fragmented over UDP, unanswered, until it timed out.
//!
//! The TCP path to such a UE is the connection the P-CSCF opens from its
//! protected client port to the UE's protected server port, the one its other
//! TCP requests take. So the switch opens (or finds open) that connection in
//! the outbound pool, and only then commits the request to TCP, addressed to
//! the UE's protected server port: the send then leaves on that connection, and
//! the Via names the protected server port as for any request to the UE. When
//! the connection cannot be opened, or the association carries no TCP, the
//! request stays on UDP and the reason is logged.

use super::*;

/// [`super::mtu_tcp_upgrade`], except toward a UE with a P-CSCF security
/// association: `Some((Tcp, ue_protected_server_port))` once the P-CSCF's
/// connection there is open, `None` (keep UDP, reason logged) when it cannot
/// be, or a request that does not need the switch.
pub(in crate::dispatcher) fn over_mtu_upgrade(
    state: &DispatcherState,
    outbound_transport: Transport,
    serialized_len: usize,
    target_uri_string: &str,
    destination: SocketAddr,
) -> Option<(Transport, SocketAddr)> {
    match protected_over_mtu(state, outbound_transport, serialized_len, destination) {
        ProtectedOverMtu::NotProtected => mtu_tcp_upgrade(
            state.mtu,
            outbound_transport,
            serialized_len,
            target_uri_string,
            destination,
            &state.dns_resolver,
        ),
        ProtectedOverMtu::Tcp(tcp) => Some((Transport::Tcp, tcp)),
        ProtectedOverMtu::KeepUdp => None,
    }
}

/// What the switch does toward a destination with a security association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtectedOverMtu {
    /// No P-CSCF association for the destination, or no switch wanted: the
    /// generic switch decides.
    NotProtected,
    /// Send over TCP to this address, the UE's protected server port.
    Tcp(SocketAddr),
    /// Stay on UDP; the reason is logged.
    KeepUdp,
}

fn protected_over_mtu(
    state: &DispatcherState,
    outbound_transport: Transport,
    serialized_len: usize,
    destination: SocketAddr,
) -> ProtectedOverMtu {
    let (Some(mtu), Some(manager)) = (state.mtu, state.ipsec_manager.as_deref()) else {
        return ProtectedOverMtu::NotProtected;
    };
    if outbound_transport != Transport::Udp || !over_mtu(serialized_len, mtu) {
        return ProtectedOverMtu::NotProtected;
    }
    let Some(pair) = manager.find_sa_by_ue(&destination.ip(), destination.port()) else {
        return ProtectedOverMtu::NotProtected;
    };
    match pair.tcp_flow_to_ue() {
        crate::ipsec::FlowToUe::NotProtected => ProtectedOverMtu::NotProtected,
        crate::ipsec::FlowToUe::Unusable(protocol) => {
            warn!(
                serialized_len, mtu, %destination, %protocol,
                "transport: forced UDP over-MTU send (the UE's security association carries no TCP)"
            );
            ProtectedOverMtu::KeepUdp
        }
        crate::ipsec::FlowToUe::Protected {
            local,
            destination: tcp,
        } => {
            // A connect can take the pool's whole connect timeout, so it runs
            // released from the interpreter (never blocking while attached).
            let opened = crate::script::blocking::block_on_released(
                state.connection_pool.connect_tcp_from(local, tcp),
            );
            match opened {
                Ok(connection_id) => {
                    debug!(
                        serialized_len, mtu, %destination, to = %tcp, %local,
                        connection_id = ?connection_id,
                        "over-MTU UDP request to a protected UE → TCP on the P-CSCF's connection \
                         to its protected server port"
                    );
                    ProtectedOverMtu::Tcp(tcp)
                }
                Err(error) => {
                    warn!(
                        serialized_len, mtu, %destination, to = %tcp, %local, %error,
                        "transport: forced UDP over-MTU send (the TCP connection from the \
                         protected client port to the UE's protected server port could not be \
                         opened)"
                    );
                    ProtectedOverMtu::KeepUdp
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "over_mtu_tests.rs"]
mod tests;
