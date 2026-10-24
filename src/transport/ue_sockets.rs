//! UDP sockets opened at run time, one per address, for outbound registrations
//! that each register from an address of their own.
//!
//! A configured `listen.udp` listener is bound once at startup and lives for
//! the life of the process. An outbound registration with a `local_addr` needs
//! sockets on *its* address instead (the plain SIP port, and with IPsec
//! sec-agree its protected client and server ports, 3GPP TS 33.203 §7.1), and
//! a process acting as many UEs needs hundreds of them, appearing and moving as
//! the addresses do. [`UeSockets`] holds those: the registration loop states
//! the full set it wants on every tick through [`UeSockets::reconcile`], and
//! the set converges on it.
//!
//! Each socket has one worker ([`udp::listen_one`]), bound with
//! `IP_FREEBIND` so it binds before its address exists on the host. A socket
//! is torn down by dropping its map entry: that drops the only long-lived
//! sender of the worker's outbound channel, the worker sees the channel close
//! and returns, and the socket's descriptor closes with it.
//!
//! The [`OutboundRouter`](super::OutboundRouter) consults this map only after
//! its static per-listener map missed, so a deployment without per-UE
//! addresses (`udp_dynamic: None`) sends exactly as before.
//!
//! A registration over TCP gets listeners instead, held by the stream half
//! ([`super::ue_streams`]) once the server attaches it
//! ([`UeSockets::attach_tcp`]); the identity checks here answer for both.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use tracing::{debug, error, info};

use super::acl::TransportAcl;
use super::udp::{self, UdpOutbound};
use super::ue_streams::{UeListeners, UeTcpContext, UeTcpPlan};
use super::{InboundMessage, OutboundMessage};

/// The run-time UDP sockets, keyed by the exact address each is bound to.
pub struct UeSockets {
    /// Bound socket address to the channel of the worker that owns it.
    sockets: DashMap<SocketAddr, UdpOutbound>,
    /// How many sockets each IP holds, for a host-only identity match
    /// ([`contains_ip`](Self::contains_ip)) without scanning `sockets`.
    ips: DashMap<IpAddr, usize>,
    /// Addresses a configured `listen.udp` listener is bound to exactly. Never
    /// opened here: the configured listener serves them already (static wins).
    static_addrs: HashSet<SocketAddr>,
    /// Addresses whose last bind failed, so a bind failing every tick is
    /// logged once rather than every five seconds.
    bind_failures: DashMap<SocketAddr, ()>,
    inbound_tx: flume::Sender<InboundMessage>,
    acl: Arc<TransportAcl>,
    tos: Option<u32>,
    recv_buffer_bytes: usize,
    /// The TCP listeners, once [`attach_tcp`](Self::attach_tcp) supplied what
    /// they share with the configured TCP side.
    tcp: OnceLock<UeListeners>,
}

/// What one [`UeSockets::reconcile`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Sockets opened by this pass.
    pub opened: usize,
    /// Sockets closed by this pass.
    pub closed: usize,
    /// Wanted addresses that could not be bound. Their owners cannot send this
    /// tick.
    pub failed: HashSet<SocketAddr>,
}

impl UeSockets {
    /// An empty set. `static_addrs` are the configured `listen.udp` addresses,
    /// which are never opened here.
    pub fn new(
        inbound_tx: flume::Sender<InboundMessage>,
        acl: Arc<TransportAcl>,
        tos: Option<u32>,
        recv_buffer_bytes: usize,
        static_addrs: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        Self {
            sockets: DashMap::new(),
            ips: DashMap::new(),
            static_addrs: static_addrs.into_iter().collect(),
            bind_failures: DashMap::new(),
            inbound_tx,
            acl,
            tos,
            recv_buffer_bytes,
            tcp: OnceLock::new(),
        }
    }

    /// Give the TCP half what it shares with the configured TCP listeners.
    /// `false` when it was attached already (the first stays).
    pub fn attach_tcp(&self, context: UeTcpContext) -> bool {
        self.tcp
            .set(UeListeners::new(
                context,
                self.inbound_tx.clone(),
                Arc::clone(&self.acl),
                self.tos,
            ))
            .is_ok()
    }

    /// Converge the TCP half on `plan` ([`UeListeners`]). Without
    /// [`attach_tcp`](Self::attach_tcp) nothing can be opened, and every wanted
    /// listener is reported failed.
    pub fn reconcile_tcp(&self, plan: &UeTcpPlan) -> ReconcileOutcome {
        match self.tcp.get() {
            Some(tcp) => tcp.reconcile(plan),
            None => ReconcileOutcome {
                failed: plan.listeners.clone(),
                ..ReconcileOutcome::default()
            },
        }
    }

    /// Whether a per-UE TCP listener is open on exactly `addr`.
    pub fn contains_tcp(&self, addr: &SocketAddr) -> bool {
        self.tcp.get().is_some_and(|tcp| tcp.contains(addr))
    }

    /// Whether a per-UE UDP socket or TCP listener is open on exactly `addr`.
    pub fn contains_any(&self, addr: &SocketAddr) -> bool {
        self.contains(addr) || self.contains_tcp(addr)
    }

    /// Open per-UE TCP listeners, and the connections they accepted that are
    /// still open (leak gate, diagnostics).
    pub fn tcp_len(&self) -> (usize, usize) {
        self.tcp
            .get()
            .map_or((0, 0), |tcp| (tcp.len(), tcp.accepted_len()))
    }

    /// The pool the TCP half hands its sources to, once attached.
    pub fn tcp_pool(&self) -> Option<&Arc<super::pool::ConnectionPool>> {
        self.tcp.get().map(UeListeners::pool)
    }

    /// Converge on exactly `desired`: open every wanted address not yet open
    /// (and not served by a configured listener), close every open one no
    /// longer wanted.
    ///
    /// Idempotent and self-healing: called on every registration tick with the
    /// full set, so a bind that failed is retried on the next one. A failing
    /// address is logged once until it binds or stops being wanted. Must be
    /// called from within a Tokio runtime (it spawns the workers).
    pub fn reconcile(&self, desired: &HashSet<SocketAddr>) -> ReconcileOutcome {
        let mut outcome = ReconcileOutcome::default();

        let unwanted: Vec<SocketAddr> = self
            .sockets
            .iter()
            .map(|entry| *entry.key())
            .filter(|addr| !desired.contains(addr))
            .collect();
        for addr in unwanted {
            if self.sockets.remove(&addr).is_some() {
                self.release_ip(addr.ip());
                outcome.closed += 1;
                debug!(%addr, "closed a per-UE UDP socket");
            }
        }
        self.bind_failures.retain(|addr, _| desired.contains(addr));

        for addr in desired {
            if self.is_static(addr) || self.sockets.contains_key(addr) {
                continue;
            }
            match self.open(*addr) {
                Ok(()) => {
                    outcome.opened += 1;
                    if self.bind_failures.remove(addr).is_some() {
                        info!(%addr, "per-UE UDP socket bound after earlier failures");
                    }
                }
                Err(bind_error) => {
                    if self.bind_failures.insert(*addr, ()).is_none() {
                        error!(
                            %addr,
                            error = %bind_error,
                            "cannot bind a per-UE UDP socket; the registration using it \
                             waits until it binds (retried every tick, logged once)"
                        );
                    }
                    outcome.failed.insert(*addr);
                }
            }
        }
        outcome
    }

    fn open(&self, addr: SocketAddr) -> std::io::Result<()> {
        if addr.ip().is_unspecified() || addr.port() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{addr} is not a concrete address and port"),
            ));
        }
        let (outbound, mut receivers) = UdpOutbound::channels(1);
        let Some(receiver) = receivers.pop() else {
            return Err(std::io::Error::other("no worker channel was created"));
        };
        udp::listen_one(
            addr,
            self.inbound_tx.clone(),
            receiver,
            Arc::clone(&self.acl),
            self.tos,
            self.recv_buffer_bytes,
            true,
        )?;
        self.sockets.insert(addr, outbound);
        *self.ips.entry(addr.ip()).or_insert(0) += 1;
        debug!(%addr, "opened a per-UE UDP socket");
        Ok(())
    }

    fn release_ip(&self, ip: IpAddr) {
        self.ips.remove_if_mut(&ip, |_, count| {
            *count = count.saturating_sub(1);
            *count == 0
        });
    }

    /// The channel of the socket bound to exactly `addr`, if one is open.
    pub fn sender(&self, addr: &SocketAddr) -> Option<UdpOutbound> {
        self.sockets.get(addr).map(|entry| entry.value().clone())
    }

    /// Whether a socket is open on exactly `addr`.
    pub fn contains(&self, addr: &SocketAddr) -> bool {
        self.sockets.contains_key(addr)
    }

    /// Whether any socket or TCP listener is open on `ip`.
    pub fn contains_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains_key(&ip) || self.tcp.get().is_some_and(|tcp| tcp.contains_ip(ip))
    }

    /// Whether `addr` is served by a configured listener rather than here:
    /// one bound to exactly it, or to the wildcard address of its family on
    /// its port, which a bind here would collide with.
    pub fn is_static(&self, addr: &SocketAddr) -> bool {
        let wildcard = SocketAddr::new(
            match addr.ip() {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            addr.port(),
        );
        self.static_addrs.contains(addr) || self.static_addrs.contains(&wildcard)
    }

    /// Number of open sockets (tests, diagnostics).
    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /// Whether no socket is open.
    pub fn is_empty(&self) -> bool {
        self.sockets.is_empty()
    }
}

impl std::fmt::Debug for UeSockets {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UeSockets")
            .field("sockets", &self.sockets.len())
            .field("static_addrs", &self.static_addrs.len())
            .finish()
    }
}

/// Route `message` to the run-time socket bound at its `source_local_addr`.
/// `Err(message)` hands it back when there is none, for the default path.
// flume's `SendError<T>` returns the message by design; see
// `OutboundRouter::send`.
#[allow(clippy::result_large_err)]
pub(crate) fn route(
    sockets: &UeSockets,
    message: OutboundMessage,
) -> Result<Result<(), flume::SendError<OutboundMessage>>, OutboundMessage> {
    let Some(source) = message.source_local_addr else {
        return Err(message);
    };
    match sockets.sender(&source) {
        Some(sender) => Ok(sender.send(message)),
        None => Err(message),
    }
}

#[cfg(test)]
#[path = "ue_sockets_tests.rs"]
mod tests;
