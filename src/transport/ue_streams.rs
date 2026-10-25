//! TCP listeners opened at run time for outbound registrations that each
//! register from an address of their own over TCP: the stream half of
//! [`UeSockets`](super::ue_sockets::UeSockets).
//!
//! A UE registering over TCP with IPsec sec-agree talks to its P-CSCF over two
//! connections (TS 24.229 clause 5.1.1.2.2 1 b and clause 5.2.2.2 1A b): the
//! one it opens itself, from its protected client port to the P-CSCF's
//! protected server port, carries its requests and their responses; the one
//! the P-CSCF opens, "from the P-CSCF's protected client port and the P-CSCF's
//! IP address to the UE's protected server port and the UE's IP address",
//! carries the P-CSCF's requests and the UE's responses to them. The first is
//! the outbound pool's ([`ConnectionPool::reconcile_pinned_sources`] binds its
//! source); the second needs the UE to listen, which is this: one listener on
//! the UE's protected server port (or its plain port without IPsec), bound with
//! `IP_FREEBIND` so it binds before the address exists, and served exactly like
//! a configured `listen.tcp` connection once accepted.
//!
//! A listener is torn down by dropping its map entry: the accept task is
//! aborted, which closes the listening socket, and every connection it accepted
//! is told to close ([`disconnect::close_connection`]).

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{debug, error, info};

use super::acl::TransportAcl;
use super::crlf_keepalive::CrlfPongTracker;
use super::disconnect;
use super::pool::ConnectionPool;
use super::send_queue::SendQueue;
use super::stream::{serve_registered_sip_stream, StreamContext};
use super::ue_sockets::ReconcileOutcome;
use super::{
    configure_tcp_socket, next_connection_id, ConnectionId, InboundMessage, StreamConnections,
    Transport,
};

/// What the per-UE TCP side shares with the configured TCP listeners.
pub struct UeTcpContext {
    /// The TCP connection map the TCP distributor writes responses through.
    pub connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
    pub stream_connections: StreamConnections,
    /// The outbound pool the UE's own connections are opened through.
    pub pool: Arc<ConnectionPool>,
    pub crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    /// Addresses a configured `listen.tcp` listener is bound to. Never opened
    /// here (static wins), as for UDP.
    pub static_addrs: HashSet<SocketAddr>,
}

/// What the per-UE TCP side should hold after one reconcile.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UeTcpPlan {
    /// Where to listen: each TCP UE's protected server port, or its plain port
    /// without IPsec.
    pub listeners: HashSet<SocketAddr>,
    /// The local sources a UE's own connection may leave from: its plain port
    /// and its protected client ports.
    pub sources: HashSet<SocketAddr>,
    /// The sources whose open connection is still in use; a connection from
    /// any other source in `sources` (or no longer in it) is closed.
    pub keep: HashSet<SocketAddr>,
}

/// The run-time TCP listeners, keyed by the exact address each is bound to.
pub(crate) struct UeListeners {
    context: UeTcpContext,
    listeners: DashMap<SocketAddr, UeListener>,
    /// Every connection a listener here accepted that is still open, with the
    /// listener it came in on.
    accepted: Arc<DashMap<ConnectionId, SocketAddr>>,
    /// Addresses whose last bind failed, logged once until they bind.
    bind_failures: DashMap<SocketAddr, ()>,
    inbound_tx: flume::Sender<InboundMessage>,
    acl: Arc<TransportAcl>,
    tos: Option<u32>,
    /// Holds each accepted connection's task before it serves, for a test to
    /// close the listener inside that window.
    #[cfg(test)]
    hold_before_serve: std::sync::Mutex<Option<Arc<tokio::sync::Semaphore>>>,
}

/// One listener: its accept task, and the connections it accepted.
struct UeListener {
    address: SocketAddr,
    accept_task: tokio::task::AbortHandle,
    accepted: Arc<DashMap<ConnectionId, SocketAddr>>,
    /// Set once the listener is closing, so an accept that lands while it is
    /// closes the connection itself (see [`accept_loop`]).
    closed: Arc<AtomicBool>,
}

impl Drop for UeListener {
    fn drop(&mut self) {
        // Flag first, then close what is entered: an accept either is entered
        // before the flag, and is found here, or reads the flag after entering
        // itself and closes on its own. Both sides are SeqCst.
        self.closed.store(true, Ordering::SeqCst);
        self.accept_task.abort();
        close_accepted_on(&self.accepted, |listener| listener == self.address);
    }
}

/// Signal every accepted connection whose listener `matches` to close.
fn close_accepted_on(
    accepted: &DashMap<ConnectionId, SocketAddr>,
    matches: impl Fn(SocketAddr) -> bool,
) -> usize {
    let closing: Vec<ConnectionId> = accepted
        .iter()
        .filter(|entry| matches(*entry.value()))
        .map(|entry| *entry.key())
        .collect();
    closing
        .into_iter()
        .filter(|connection_id| {
            disconnect::close_connection(*connection_id, "the per-UE TCP listener closed")
        })
        .count()
}

/// Removes an accepted connection from the store when its task ends, on every
/// exit path.
struct AcceptedGuard {
    accepted: Arc<DashMap<ConnectionId, SocketAddr>>,
    connection_id: ConnectionId,
}

impl Drop for AcceptedGuard {
    fn drop(&mut self) {
        self.accepted.remove(&self.connection_id);
    }
}

impl UeListeners {
    pub(crate) fn new(
        context: UeTcpContext,
        inbound_tx: flume::Sender<InboundMessage>,
        acl: Arc<TransportAcl>,
        tos: Option<u32>,
    ) -> Self {
        Self {
            context,
            listeners: DashMap::new(),
            accepted: Arc::new(DashMap::new()),
            bind_failures: DashMap::new(),
            inbound_tx,
            acl,
            tos,
            #[cfg(test)]
            hold_before_serve: std::sync::Mutex::new(None),
        }
    }

    /// Converge on `plan`: open every wanted listener not yet open, close every
    /// open one no longer wanted (with the connections it accepted), and hand
    /// the sources to the pool. Idempotent, called on every registration tick;
    /// a listener that failed to bind is retried on the next. Must be called
    /// from within a Tokio runtime.
    pub(crate) fn reconcile(&self, plan: &UeTcpPlan) -> ReconcileOutcome {
        let mut outcome = ReconcileOutcome::default();
        let unwanted: Vec<SocketAddr> = self
            .listeners
            .iter()
            .map(|entry| *entry.key())
            .filter(|addr| !plan.listeners.contains(addr))
            .collect();
        for addr in unwanted {
            if self.listeners.remove(&addr).is_some() {
                outcome.closed += 1;
                debug!(%addr, "closed a per-UE TCP listener");
            }
        }
        // A connection accepted in the instant its listener was dropped, before
        // it could be told to close, goes on the next pass.
        close_accepted_on(&self.accepted, |listener| {
            !self.listeners.contains_key(&listener)
        });
        self.bind_failures
            .retain(|addr, _| plan.listeners.contains(addr));

        for addr in &plan.listeners {
            if self.is_static(addr) || self.listeners.contains_key(addr) {
                continue;
            }
            match self.open(*addr) {
                Ok(()) => {
                    outcome.opened += 1;
                    if self.bind_failures.remove(addr).is_some() {
                        info!(%addr, "per-UE TCP listener bound after earlier failures");
                    }
                }
                Err(bind_error) => {
                    if self.bind_failures.insert(*addr, ()).is_none() {
                        error!(
                            %addr,
                            error = %bind_error,
                            "cannot bind a per-UE TCP listener; the registration using it \
                             waits until it binds (retried every tick, logged once)"
                        );
                    }
                    outcome.failed.insert(*addr);
                }
            }
        }
        self.context
            .pool
            .reconcile_pinned_sources(plan.sources.clone(), &plan.keep);
        outcome
    }

    fn open(&self, addr: SocketAddr) -> std::io::Result<()> {
        if addr.ip().is_unspecified() || addr.port() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{addr} is not a concrete address and port"),
            ));
        }
        let listener = bind_freebind_listener(addr, self.tos)?;
        let closed = Arc::new(AtomicBool::new(false));
        let accept_task = tokio::spawn(accept_loop(AcceptLoop {
            listener,
            address: addr,
            closed: Arc::clone(&closed),
            accepted: Arc::clone(&self.accepted),
            inbound_tx: self.inbound_tx.clone(),
            connection_map: Arc::clone(&self.context.connection_map),
            stream_connections: self.context.stream_connections.clone(),
            crlf_pong_tracker: self.context.crlf_pong_tracker.clone(),
            acl: Arc::clone(&self.acl),
            tos: self.tos,
            #[cfg(test)]
            hold_before_serve: self
                .hold_before_serve
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        }))
        .abort_handle();
        self.listeners.insert(
            addr,
            UeListener {
                address: addr,
                accept_task,
                accepted: Arc::clone(&self.accepted),
                closed,
            },
        );
        debug!(%addr, "opened a per-UE TCP listener");
        Ok(())
    }

    /// Whether a configured `listen.tcp` listener serves `addr`: bound to it
    /// exactly, or to the wildcard of its family on its port.
    fn is_static(&self, addr: &SocketAddr) -> bool {
        let wildcard = SocketAddr::new(
            match addr.ip() {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            addr.port(),
        );
        self.context.static_addrs.contains(addr) || self.context.static_addrs.contains(&wildcard)
    }

    /// Whether a listener is open on exactly `addr`.
    pub(crate) fn contains(&self, addr: &SocketAddr) -> bool {
        self.listeners.contains_key(addr)
    }

    /// Whether any listener is open on `ip`.
    pub(crate) fn contains_ip(&self, ip: IpAddr) -> bool {
        self.listeners.iter().any(|entry| entry.key().ip() == ip)
    }

    /// Open listeners (leak gate, diagnostics).
    pub(crate) fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Open connections the listeners accepted (leak gate, diagnostics).
    pub(crate) fn accepted_len(&self) -> usize {
        self.accepted.len()
    }

    /// The pool the UE's own connections go through.
    pub(crate) fn pool(&self) -> &Arc<ConnectionPool> {
        &self.context.pool
    }

    /// Hold the task of every connection a listener opened from now on
    /// accepts until `hold` has a permit, before it serves.
    #[cfg(test)]
    pub(crate) fn hold_before_serve(&self, hold: Arc<tokio::sync::Semaphore>) {
        *self
            .hold_before_serve
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hold);
    }
}

/// A TCP listener on `addr` with `IP_FREEBIND`, so it binds before the address
/// is on the host, and `SO_REUSEADDR` + `SO_REUSEPORT`, so the pool can open
/// the UE's own connection from the same address and port (a plain-port
/// entry's Contact is where it listens and where it connects from).
fn bind_freebind_listener(
    addr: SocketAddr,
    tos: Option<u32>,
) -> std::io::Result<tokio::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    super::udp::set_freebind(&socket, addr)?;
    socket.set_nonblocking(true)?;
    if let Some(tos) = tos {
        super::apply_tos(&socket2::SockRef::from(&socket), tos);
    }
    socket.bind(&socket2::SockAddr::from(addr))?;
    socket.listen(1024)?;
    tokio::net::TcpListener::from_std(socket.into())
}

/// What one accept task owns.
struct AcceptLoop {
    listener: tokio::net::TcpListener,
    address: SocketAddr,
    closed: Arc<AtomicBool>,
    accepted: Arc<DashMap<ConnectionId, SocketAddr>>,
    inbound_tx: flume::Sender<InboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
    stream_connections: StreamConnections,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    acl: Arc<TransportAcl>,
    tos: Option<u32>,
    #[cfg(test)]
    hold_before_serve: Option<Arc<tokio::sync::Semaphore>>,
}

/// Accept connections until aborted, serving each as a `listen.tcp`
/// connection is served.
///
/// A connection is closable from the instant it is accepted: its closer is
/// registered and it is entered in `accepted` here, before its task is
/// spawned, so a listener dropped at any point after finds and closes it, and
/// the close is kept until the task serves the connection. Registering inside
/// the task instead lost a close sent before the task first ran, and the
/// connection then lived until the peer closed it.
async fn accept_loop(context: AcceptLoop) {
    loop {
        let (socket, remote_addr) = match context.listener.accept().await {
            Ok(accepted) => accepted,
            Err(accept_error) => {
                error!(addr = %context.address, "per-UE TCP accept error: {accept_error}");
                continue;
            }
        };
        if !context.acl.is_allowed(remote_addr.ip()) {
            debug!("per-UE TCP rejected {remote_addr} by ACL");
            continue;
        }
        let mut permit = match crate::security::try_accept_connection(remote_addr.ip()) {
            Ok(permit) => permit,
            Err(reason) => {
                debug!("per-UE TCP refused {remote_addr} by connection limit: {reason}");
                crate::security::record_connection_refused(reason);
                continue;
            }
        };
        configure_tcp_socket(&socket, context.tos);
        let connection_id = next_connection_id();
        let closer =
            disconnect::ConnectionCloser::register(connection_id, remote_addr, Transport::Tcp);
        context.accepted.insert(connection_id, context.address);
        let guard = AcceptedGuard {
            accepted: Arc::clone(&context.accepted),
            connection_id,
        };
        // The listener began closing before this connection was entered, so it
        // may not have seen it: drop it here (the socket, the guard and the
        // closer go with this iteration).
        if context.closed.load(Ordering::SeqCst) {
            debug!(peer = %remote_addr, "per-UE TCP connection accepted as its listener closed");
            return;
        }
        let local_addr = socket.local_addr().unwrap_or(context.address);
        let inbound_tx = context.inbound_tx.clone();
        let connection_map = Arc::clone(&context.connection_map);
        let stream_connections = context.stream_connections.clone();
        let crlf_pong_tracker = context.crlf_pong_tracker.clone();
        #[cfg(test)]
        let hold_before_serve = context.hold_before_serve.clone();
        debug!(local = %local_addr, peer = %remote_addr, ?connection_id, "per-UE TCP accepted");
        tokio::spawn(async move {
            let _guard = guard;
            #[cfg(test)]
            if let Some(hold) = hold_before_serve {
                let _ = hold.acquire().await;
            }
            // Served without the first-line sniff of a configured listener:
            // registered for closing from its first instant, and the framer
            // drops anything that is not SIP.
            permit.handshake_done();
            let _permit = permit;
            let (reader, writer) = socket.into_split();
            serve_registered_sip_stream(
                reader,
                writer,
                StreamContext {
                    transport: Transport::Tcp,
                    client_transport: None,
                    connection_id,
                    local_addr,
                    remote_addr,
                },
                closer,
                bytes::BytesMut::new(),
                inbound_tx,
                connection_map,
                Some(stream_connections),
                crlf_pong_tracker,
                None,
            )
            .await;
        });
    }
}

#[cfg(test)]
#[path = "ue_streams_tests.rs"]
mod tests;
