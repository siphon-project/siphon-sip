//! TCP on the protected ports of a UDP IMS UE entry.
//!
//! The security associations of TS 33.203 are "shared by TCP and UDP" (clause
//! 6.3): one SA set protects both, so a UE that registered over UDP still has a
//! TCP path to its P-CSCF. It matters because a request over the path MTU leaves
//! over TCP (RFC 3261 clause 18.1.1): a large reg-event NOTIFY from the P-CSCF
//! arrives as a connection to the UE's protected server port (TS 24.229 clause
//! 5.2.2.2 1A b: "from the P-CSCF's protected client port ... to the UE's
//! protected server port"), and the UE's own large REGISTER leaves from its
//! protected client port to the P-CSCF's protected server port (clause 5.1.1.2.2
//! 1 b). Both used to fail for a UDP entry: nothing listened for TCP on
//! `ue_port_s` (connection refused, so the P-CSCF fell back to fragmented UDP),
//! and the REGISTER stayed UDP whatever its size.
//!
//! This module is the plan for the first: [`RegistrantManager::plan_protected_tcp`]
//! adds, for a UDP IPsec entry that holds an SA set, a TCP listener on its
//! protected server port, and the sources its own TCP connection may leave from
//! (its client ports), to the stream plan the registration loop reconciles every
//! tick ([`RegistrantManager::ue_stream_plan`]). The listener lives as long as the
//! entry holds an SA set: it is opened when the first one is taken into use and
//! closed, with the connections it accepted, when the last is deleted, the entry
//! is removed or moves off its address. Requests arriving on it are dispatched
//! as the ones on the protected UDP port are, with the entry attributed by the
//! address and port they arrived on, and responses go back on the connection.
//!
//! The second is [`BuiltRegister::over_mtu_tcp`]: with `listen.mtu` set, a
//! REGISTER over an SA set (the refresh or re-authentication, and the
//! authenticated one on the temporary set of a challenge) whose length is over
//! the threshold the relay uses ([`crate::transport::mtu::over_mtu`]) goes over
//! TCP from the protected client port of that set, with the Via changed to TCP.
//! The connection is the pool's, bound to that source, kept until the set goes
//! and reused by every request in between. When it cannot be opened the REGISTER
//! goes over UDP as it would have, with a warning (RFC 3261 clause 18.1.1:
//! "SHOULD retry the request, using UDP"). Not switched: the de-REGISTER (small,
//! and sent as the process stops) and requests a script sends over
//! `registration.flow()`, which keep the flow's transport.

use std::net::{IpAddr, SocketAddr};

use super::{RegistrantEntry, RegistrantManager};
use crate::transport::ue_streams::UeTcpPlan;
use crate::transport::Transport;

impl RegistrantManager {
    /// Add what a UDP IPsec `entry` needs over TCP to `plan`: with
    /// `own_connections` (an MTU is set, so its REGISTERs may go over TCP) its
    /// protected client ports as bindable sources, always, so a connection to
    /// the P-CSCF binds one from its first use; and, while it holds an SA set, a
    /// listener on its protected server port and the client port of every set
    /// as a connection to keep.
    ///
    /// No listener without a set (the P-CSCF cannot reach the protected port
    /// before one exists, and an unprotected port takes no TCP). Nothing at
    /// all without IPsec, on another transport (a TCP entry has its own
    /// plan), or without an address: its own `local_addr`, else the process's
    /// UE address `process_ue_ip` unless the entry requires an address of its
    /// own, as for [`ue_socket_plan`](Self::ue_socket_plan).
    pub(super) fn plan_protected_tcp(
        entry: &RegistrantEntry,
        process_ue_ip: Option<IpAddr>,
        own_connections: bool,
        plan: &mut UeTcpPlan,
    ) {
        if entry.transport != Transport::Udp {
            return;
        }
        let Some(ipsec) = entry.ue_ipsec.as_ref() else {
            return;
        };
        let ip = match (entry.local_addr, process_ue_ip) {
            (Some(own), _) => own,
            (None, Some(process)) if !entry.require_local_addr && !process.is_unspecified() => {
                process
            }
            _ => return,
        };
        let on_address = |port: u16| SocketAddr::new(ip, port);
        if own_connections {
            plan.sources
                .extend(ipsec.client_ports.iter().copied().map(on_address));
        }
        let keys = ipsec.sa_sets.keys();
        if keys.is_empty() {
            return;
        }
        plan.listeners.insert(on_address(ipsec.ue_port_s));
        plan.keep
            .extend(keys.into_iter().map(|key| on_address(key.ue_port_c)));
    }
}

/// The TCP path of a REGISTER over an SA set that is over the MTU: the
/// connection from the UE's protected client port to the P-CSCF's protected
/// server port, which the SA set carries like UDP (TS 33.203 clause 7.1, "the
/// transport protocol selector shall allow UDP and TCP"; TS 24.229 clause
/// 5.1.1.2.2 1 b, the connection "established by the UE, i.e. from the UE's
/// protected client port and the UE's IP address to the P-CSCF's protected
/// server port").
///
/// The same connection serves every later request until the SA set changes:
/// the registration loop keeps the pooled connection from a held set's client
/// port and closes it when the set goes ([`UeTcpPlan::keep`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverMtuTcp {
    /// The UE's protected client port on its address: the connection's source.
    pub source: SocketAddr,
    /// The P-CSCF's protected server port: the connection's destination.
    pub destination: SocketAddr,
    /// The Via the request carries once it moves to TCP (RFC 3261 clause
    /// 18.1.1: "the value in the top Via MUST be changed").
    via: String,
}

impl OverMtuTcp {
    /// Open, or find open, the connection. `true` when it is up and the request
    /// may go over it.
    ///
    /// RFC 3261 clause 18.1.1: a request moved to TCP because of its size, that
    /// would otherwise have gone over UDP, "SHOULD retry the request, using
    /// UDP" when the attempt to establish the connection fails (ICMP Protocol
    /// Not Supported, or a TCP reset). siphon retries over UDP on any failure
    /// to connect, a timeout included: the request is not lost, it goes as it
    /// would have without the switch. The pool backs off a destination that
    /// failed, so a P-CSCF without TCP costs one attempt, not one per REGISTER.
    pub async fn connect(&self, pool: &crate::transport::pool::ConnectionPool, aor: &str) -> bool {
        match pool.connect_tcp_from(self.source, self.destination).await {
            Ok(connection_id) => {
                tracing::debug!(
                    aor = %aor,
                    source = %self.source,
                    destination = %self.destination,
                    ?connection_id,
                    "over-MTU REGISTER over its SA set goes over TCP from the protected client \
                     port to the P-CSCF's protected server port"
                );
                true
            }
            Err(error) => {
                tracing::warn!(
                    aor = %aor,
                    source = %self.source,
                    destination = %self.destination,
                    %error,
                    "over-MTU REGISTER: the TCP connection over the SA set could not be opened; \
                     retrying the REGISTER over UDP (RFC 3261 clause 18.1.1)"
                );
                false
            }
        }
    }

    /// Put the TCP Via on `message`.
    pub fn apply(&self, message: &mut crate::sip::message::SipMessage) {
        message.headers.set("Via", self.via.clone());
    }
}

impl super::BuiltRegister {
    /// The TCP path this REGISTER takes, when it leaves over an SA set on UDP
    /// and its serialised length is over the MTU threshold (RFC 3261 clause
    /// 18.1.1; the threshold is the one the relay uses,
    /// [`crate::transport::mtu::over_mtu`]). `None` with no MTU configured
    /// (`listen.mtu`), for a REGISTER that is not over an SA set, and for one
    /// already over a stream transport.
    pub fn over_mtu_tcp(&self, mtu: Option<u16>) -> Option<OverMtuTcp> {
        let mtu = mtu?;
        if !self.over_sa_set || self.transport != Transport::Udp {
            return None;
        }
        let source = self.source_local_addr?;
        if !crate::transport::mtu::over_mtu(self.message.to_bytes().len(), mtu) {
            return None;
        }
        Some(OverMtuTcp {
            source,
            destination: self.destination,
            via: format!("SIP/2.0/TCP {};branch={};rport", self.sent_by, self.branch),
        })
    }

    /// This REGISTER over TCP on `path`: the top Via says TCP, so its client
    /// transaction runs the reliable-transport timers (no Timer E).
    pub fn over_tcp(mut self, path: &OverMtuTcp) -> Self {
        path.apply(&mut self.message);
        self.transport = Transport::Tcp;
        self
    }
}

#[cfg(test)]
#[path = "protected_tcp_tests.rs"]
mod tests;
