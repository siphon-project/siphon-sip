/// Transport layer — UDP, TCP, TLS, WebSocket, WSS, SCTP.
/// Each transport sends inbound SIP messages to the core via a channel
/// and receives outbound messages via a per-connection sender.
pub mod udp;
pub mod tcp;
pub mod tls;
pub mod ws;
pub mod sctp;
pub mod pool;
pub mod rate_limit;
pub mod acl;
pub mod flow;
pub mod crlf_keepalive;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use socket2::SockRef;
use tracing::warn;

/// Global monotonic counter for assigning connection-oriented connection IDs.
/// Shared across TCP and TLS listeners so IDs are globally unique.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_connection_id() -> ConnectionId {
    ConnectionId(NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed))
}

/// Default idle timeout for connection-oriented transports (TCP/TLS/WS/WSS).
/// Connections with no activity for this duration are closed to prevent
/// zombie connections from accumulating (especially behind NAT).
pub const CONNECTION_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Apply IP_TOS / IPV6_TCLASS on a socket2 reference.
///
/// `tos` is the full 8-bit TOS byte (DSCP << 2).  Use [`crate::config::dscp_to_tos`]
/// to convert from a 6-bit DSCP value.
///
/// socket2 0.6 only exposes `set_tos_v4` (IP_TOS).  For IPv6 sockets we
/// fall back to a raw `setsockopt(IPV6_TCLASS)` via `set_tos_v4` which on
/// Linux works on dual-stack sockets.  If the v4 call fails we log and
/// continue — TOS is best-effort (the kernel may ignore it without
/// `CAP_NET_ADMIN` depending on DSCP value).
pub fn apply_tos(sock_ref: &SockRef<'_>, tos: u32) {
    if let Err(error) = sock_ref.set_tos_v4(tos) {
        warn!(tos, "failed to set IP_TOS/IPV6_TCLASS: {error}");
    }
}

/// Apply TCP_NODELAY, SO_KEEPALIVE, and optional TOS to an accepted TCP socket.
/// Called after `TcpListener::accept()` for TCP, TLS, WS, and WSS connections.
pub fn configure_tcp_socket(socket: &tokio::net::TcpStream, tos: Option<u32>) {
    let sock_ref = SockRef::from(socket);

    // Disable Nagle — SIP is request-response, every message should go immediately.
    if let Err(error) = sock_ref.set_tcp_nodelay(true) {
        warn!("failed to set TCP_NODELAY: {}", error);
    }

    // Enable SO_KEEPALIVE to detect dead connections behind NAT/firewalls.
    if let Err(error) = sock_ref.set_keepalive(true) {
        warn!("failed to set SO_KEEPALIVE: {}", error);
    }

    // Tune keepalive intervals: probe after 60s idle, every 10s, 3 retries.
    // Total detection time: 60 + 10*3 = 90 seconds.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    {
        if let Err(error) = sock_ref.set_tcp_keepalive(
            &socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(60))
                .with_interval(Duration::from_secs(10))
                .with_retries(3),
        ) {
            warn!("failed to set TCP keepalive params: {}", error);
        }
    }

    // DSCP / DiffServ marking (RFC 4594) on accepted connections (belt-and-suspenders:
    // Linux inherits TOS from the listener, but we set it explicitly for safety).
    if let Some(tos) = tos {
        apply_tos(&sock_ref, tos);
    }
}

/// Uniquely identifies a transport connection.
/// For UDP: hashed from (local_addr, remote_addr).
/// For TCP/TLS: monotonic counter assigned at accept().
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ConnectionId(pub u64);

/// An inbound SIP datagram or stream segment, including routing metadata.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub connection_id: ConnectionId,
    pub transport: Transport,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub data: Bytes,
}

/// Transport protocol variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    WebSocket,
    WebSocketSecure,
    Sctp,
}

impl std::fmt::Display for Transport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Udp => write!(formatter, "UDP"),
            Transport::Tcp => write!(formatter, "TCP"),
            Transport::Tls => write!(formatter, "TLS"),
            Transport::WebSocket => write!(formatter, "WS"),
            Transport::WebSocketSecure => write!(formatter, "WSS"),
            Transport::Sctp => write!(formatter, "SCTP"),
        }
    }
}

/// A message to be sent outbound on a specific connection.
#[derive(Debug)]
pub struct OutboundMessage {
    pub connection_id: ConnectionId,
    pub transport: Transport,
    pub destination: SocketAddr,
    pub data: Bytes,
    /// Local socket the message must egress from.  When `Some(addr)`,
    /// the [`OutboundRouter`] forwards to the UDP listener bound to
    /// `addr`.  Required for IPsec-protected replies (3GPP TS 33.203
    /// §7.4: a response must leave on the same SA's local endpoint
    /// that the request arrived on, otherwise the kernel egress XFRM
    /// policy won't match).  When `None`, the message goes to the
    /// default UDP channel (typically the first listener configured).
    pub source_local_addr: Option<SocketAddr>,
}

/// Routes outbound messages to the correct transport channel.
///
/// UDP traffic supports per-listener routing: when a message carries
/// `source_local_addr = Some(addr)` and a listener is bound to that
/// address (registered via `udp_by_local`), the message is delivered
/// to that listener's private channel.  Otherwise it falls back to
/// the default UDP channel.
pub struct OutboundRouter {
    /// Default UDP sender — used for messages without a specific
    /// `source_local_addr` and for any address not in `udp_by_local`.
    pub udp: flume::Sender<OutboundMessage>,
    /// Per-listener UDP channels keyed by local socket address.
    /// Populated at server startup; empty in test fixtures.
    pub udp_by_local: std::collections::HashMap<SocketAddr, flume::Sender<OutboundMessage>>,
    pub tcp: flume::Sender<OutboundMessage>,
    pub tls: flume::Sender<OutboundMessage>,
    pub ws: flume::Sender<OutboundMessage>,
    pub wss: flume::Sender<OutboundMessage>,
    pub sctp: flume::Sender<OutboundMessage>,
}

impl OutboundRouter {
    pub fn send(&self, message: OutboundMessage) -> Result<(), flume::SendError<OutboundMessage>> {
        match message.transport {
            Transport::Udp => {
                // Fast path for the common (non-P-CSCF) case: when the
                // server didn't register per-listener channels, skip the
                // HashMap entirely and use the default sender.  Branch
                // predictor pins this — it's the steady-state hot path
                // for proxy/B2BUA workloads, where adding a HashMap
                // lookup per response cost ~15–20 % CPU at 10 kcps in
                // the README scale baseline.
                if !self.udp_by_local.is_empty() {
                    if let Some(source) = message.source_local_addr {
                        if let Some(sender) = self.udp_by_local.get(&source) {
                            return sender.send(message);
                        }
                    }
                }
                self.udp.send(message)
            }
            Transport::Tcp => self.tcp.send(message),
            Transport::Tls => self.tls.send(message),
            Transport::WebSocket => self.ws.send(message),
            Transport::WebSocketSecure => self.wss.send(message),
            Transport::Sctp => self.sctp.send(message),
        }
    }
}

/// Cross-transport registry of live stream connections, keyed by the peer's
/// socket address.  Supersedes the former TLS-only `tls_addr_map`: TLS and
/// WS/WSS listeners register their accepted (inbound) connections here, and
/// the connection pool registers the outbound TLS connections it creates, so
/// the relay path can reuse an existing connection instead of dialing a new
/// one.  For WebSocket this is the *only* way to reach a UE — the connection
/// is client-initiated and can never be re-opened by the server (RFC 7118 §5
/// / RFC 5626 connection reuse).
///
/// The value carries the [`Transport`] alongside the [`ConnectionId`] so
/// consumers (relay reuse, NAT keepalive, registrant liveness, `Flow.is_alive`)
/// can discriminate which kind of connection a given peer holds.  Cheap to
/// clone — it is an `Arc` around the shared map.
#[derive(Clone, Default)]
pub struct StreamConnections {
    map: Arc<DashMap<SocketAddr, (Transport, ConnectionId)>>,
}

impl StreamConnections {
    pub fn new() -> Self {
        Self { map: Arc::new(DashMap::new()) }
    }

    /// Register (or overwrite) the live connection for `peer`.  Called by the
    /// stream listeners on accept and by the pool when it opens an outbound
    /// connection.
    pub fn register(&self, peer: SocketAddr, transport: Transport, connection_id: ConnectionId) {
        self.map.insert(peer, (transport, connection_id));
    }

    /// Remove the registration for `peer` (connection closed / errored).
    pub fn unregister(&self, peer: &SocketAddr) {
        self.map.remove(peer);
    }

    /// Exact-match lookup of the connection for `peer`, if any.
    pub fn get(&self, peer: &SocketAddr) -> Option<(Transport, ConnectionId)> {
        self.map.get(peer).map(|entry| *entry.value())
    }

    /// Find a reusable `connection_id` to `destination` on `transport` —
    /// exact socket-address match first, then an IP-only fallback (handles
    /// NAT, where the Contact-URI port differs from the live source port).
    /// Both steps are filtered by `transport` so a WS connection is never
    /// returned for a TLS relay (and vice versa).
    pub fn reuse(&self, destination: SocketAddr, transport: Transport) -> Option<ConnectionId> {
        if let Some(entry) = self.map.get(&destination) {
            if entry.value().0 == transport {
                return Some(entry.value().1);
            }
        }
        self.map
            .iter()
            .find(|entry| entry.key().ip() == destination.ip() && entry.value().0 == transport)
            .map(|entry| entry.value().1)
    }

    /// Whether *any* connection from `ip` is currently registered (IP-only,
    /// transport-agnostic).  Diagnostic helper.
    pub fn has_ip(&self, ip: IpAddr) -> bool {
        self.map.iter().any(|entry| entry.key().ip() == ip)
    }

    /// Whether any `transport` connection from `ip` is currently registered.
    /// Backs registrant outbound-liveness detection: it reproduces the
    /// pre-unification `tls_addr_map` semantics exactly (that map only ever
    /// held entries of one transport per consumer), and the transport filter
    /// keeps an unrelated WS/WSS UE connection from masking a dead TLS/TCP
    /// trunk that happens to share an IP.
    pub fn has_ip_transport(&self, ip: IpAddr, transport: Transport) -> bool {
        self.map
            .iter()
            .any(|entry| entry.key().ip() == ip && entry.value().0 == transport)
    }

    /// True only when the exact `(peer, transport, connection_id)` triple is
    /// still registered — backs [`crate::script::api::registrar::PyFlow`]'s
    /// `is_alive` for stream transports.  A peer that re-registered with a new
    /// connection makes the old flow report dead.
    pub fn is_alive(&self, peer: SocketAddr, transport: Transport, connection_id: ConnectionId) -> bool {
        self.map
            .get(&peer)
            .map(|entry| *entry.value() == (transport, connection_id))
            .unwrap_or(false)
    }

    /// Number of registered connections (diagnostics / metrics).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Snapshot of every entry as `(peer, transport, connection_id)` — used for
    /// diagnostic logging only (mirrors the old `tls_addr_map` debug dump).
    pub fn entries(&self) -> Vec<(SocketAddr, Transport, ConnectionId)> {
        self.map
            .iter()
            .map(|entry| (*entry.key(), entry.value().0, entry.value().1))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn configure_tcp_socket_sets_nodelay_and_keepalive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_task = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });

        let (server_socket, _) = listener.accept().await.unwrap();
        let client_socket = connect_task.await.unwrap();

        // Apply our configuration
        configure_tcp_socket(&server_socket, None);
        configure_tcp_socket(&client_socket, None);

        // Verify TCP_NODELAY is set
        assert!(server_socket.nodelay().unwrap(), "server TCP_NODELAY should be true");
        assert!(client_socket.nodelay().unwrap(), "client TCP_NODELAY should be true");

        // Verify SO_KEEPALIVE is set via socket2
        let server_ref = SockRef::from(&server_socket);
        assert!(server_ref.keepalive().unwrap(), "server SO_KEEPALIVE should be true");
    }

    #[test]
    fn apply_tos_sets_value_on_udp_socket() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        let sock_ref = SockRef::from(&socket);
        apply_tos(&sock_ref, 96); // CS3
        let tos = sock_ref.tos_v4().unwrap();
        assert_eq!(tos, 96, "TOS should be 96 (CS3 = DSCP 24 << 2)");
    }

    #[test]
    fn apply_tos_sets_value_on_tcp_socket() {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        let sock_ref = SockRef::from(&socket);
        apply_tos(&sock_ref, 184); // EF
        let tos = sock_ref.tos_v4().unwrap();
        assert_eq!(tos, 184, "TOS should be 184 (EF = DSCP 46 << 2)");
    }

    #[tokio::test]
    async fn configure_tcp_socket_applies_tos() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_task = tokio::spawn(async move {
            tokio::net::TcpStream::connect(addr).await.unwrap()
        });

        let (server_socket, _) = listener.accept().await.unwrap();
        let _client_socket = connect_task.await.unwrap();

        configure_tcp_socket(&server_socket, Some(96));
        let sock_ref = SockRef::from(&server_socket);
        assert_eq!(sock_ref.tos_v4().unwrap(), 96, "TOS should be set by configure_tcp_socket");
    }

    #[test]
    fn transport_display_udp() {
        assert_eq!(Transport::Udp.to_string(), "UDP");
    }

    #[test]
    fn transport_display_tcp() {
        assert_eq!(Transport::Tcp.to_string(), "TCP");
    }

    #[test]
    fn transport_display_tls() {
        assert_eq!(Transport::Tls.to_string(), "TLS");
    }

    #[test]
    fn transport_display_websocket() {
        assert_eq!(Transport::WebSocket.to_string(), "WS");
    }

    #[test]
    fn transport_display_wss() {
        assert_eq!(Transport::WebSocketSecure.to_string(), "WSS");
    }

    #[test]
    fn transport_display_sctp() {
        assert_eq!(Transport::Sctp.to_string(), "SCTP");
    }

    #[test]
    fn transport_variants_are_distinct() {
        assert_ne!(Transport::Udp, Transport::Tcp);
        assert_ne!(Transport::Tcp, Transport::Tls);
        assert_ne!(Transport::Tls, Transport::WebSocket);
        assert_ne!(Transport::WebSocket, Transport::WebSocketSecure);
        assert_ne!(Transport::WebSocketSecure, Transport::Sctp);
        assert_ne!(Transport::Udp, Transport::Sctp);
    }

    #[test]
    fn transport_clone() {
        let original = Transport::Tls;
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn connection_id_equality() {
        assert_eq!(ConnectionId(42), ConnectionId(42));
        assert_ne!(ConnectionId(1), ConnectionId(2));
    }

    #[test]
    fn connection_id_hash_works() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ConnectionId(1));
        set.insert(ConnectionId(2));
        set.insert(ConnectionId(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn connection_id_debug() {
        let id = ConnectionId(12345);
        let debug = format!("{:?}", id);
        assert!(debug.contains("12345"));
    }

    #[test]
    fn inbound_message_construction() {
        let message = InboundMessage {
            connection_id: ConnectionId(1),
            transport: Transport::Udp,
            local_addr: "127.0.0.1:5060".parse().unwrap(),
            remote_addr: "192.168.1.1:50000".parse().unwrap(),
            data: Bytes::from_static(b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n"),
        };
        assert_eq!(message.connection_id, ConnectionId(1));
        assert_eq!(message.transport, Transport::Udp);
        assert_eq!(message.local_addr.port(), 5060);
        assert_eq!(message.remote_addr.port(), 50000);
        assert!(!message.data.is_empty());
    }

    #[test]
    fn outbound_message_construction() {
        let message = OutboundMessage {
            connection_id: ConnectionId(99),
            transport: Transport::Udp,
            destination: "10.0.0.1:5060".parse().unwrap(),
            data: Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"),
            source_local_addr: None,
        };
        assert_eq!(message.connection_id, ConnectionId(99));
        assert_eq!(message.transport, Transport::Udp);
        assert_eq!(message.destination.port(), 5060);
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn stream_connections_register_and_get() {
        let registry = StreamConnections::new();
        assert!(registry.is_empty());
        let peer = addr("10.0.0.1:50000");
        registry.register(peer, Transport::WebSocketSecure, ConnectionId(7));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.get(&peer), Some((Transport::WebSocketSecure, ConnectionId(7))));
        assert_eq!(registry.get(&addr("10.0.0.2:50000")), None);
    }

    #[test]
    fn stream_connections_reuse_exact_match() {
        let registry = StreamConnections::new();
        let peer = addr("10.0.0.1:50000");
        registry.register(peer, Transport::WebSocket, ConnectionId(3));
        assert_eq!(registry.reuse(peer, Transport::WebSocket), Some(ConnectionId(3)));
    }

    #[test]
    fn stream_connections_reuse_ip_only_fallback() {
        // NAT: Contact-URI port (5060) differs from the live source port (50000).
        let registry = StreamConnections::new();
        registry.register(addr("10.0.0.1:50000"), Transport::Tls, ConnectionId(9));
        // Exact match on :5060 misses, IP-only fallback finds the :50000 conn.
        assert_eq!(registry.reuse(addr("10.0.0.1:5060"), Transport::Tls), Some(ConnectionId(9)));
        // Different IP — no fallback.
        assert_eq!(registry.reuse(addr("10.0.0.2:5060"), Transport::Tls), None);
    }

    #[test]
    fn stream_connections_reuse_discriminates_transport() {
        // A WS connection must never be handed back for a TLS relay.
        let registry = StreamConnections::new();
        let peer = addr("10.0.0.1:50000");
        registry.register(peer, Transport::WebSocket, ConnectionId(4));
        assert_eq!(registry.reuse(peer, Transport::Tls), None);
        assert_eq!(registry.reuse(addr("10.0.0.1:5060"), Transport::Tls), None);
        assert_eq!(registry.reuse(peer, Transport::WebSocket), Some(ConnectionId(4)));
    }

    #[test]
    fn stream_connections_is_alive_tracks_exact_triple() {
        let registry = StreamConnections::new();
        let peer = addr("10.0.0.1:50000");
        registry.register(peer, Transport::WebSocketSecure, ConnectionId(11));
        assert!(registry.is_alive(peer, Transport::WebSocketSecure, ConnectionId(11)));
        // Wrong transport or id → not this flow.
        assert!(!registry.is_alive(peer, Transport::WebSocket, ConnectionId(11)));
        assert!(!registry.is_alive(peer, Transport::WebSocketSecure, ConnectionId(12)));
        // Peer re-registers with a fresh connection → old flow is dead.
        registry.register(peer, Transport::WebSocketSecure, ConnectionId(12));
        assert!(!registry.is_alive(peer, Transport::WebSocketSecure, ConnectionId(11)));
        assert!(registry.is_alive(peer, Transport::WebSocketSecure, ConnectionId(12)));
        // Unregistered → dead.
        registry.unregister(&peer);
        assert!(!registry.is_alive(peer, Transport::WebSocketSecure, ConnectionId(12)));
    }

    #[test]
    fn stream_connections_has_ip_is_transport_agnostic() {
        let registry = StreamConnections::new();
        registry.register(addr("10.0.0.1:50000"), Transport::WebSocket, ConnectionId(1));
        assert!(registry.has_ip("10.0.0.1".parse().unwrap()));
        assert!(!registry.has_ip("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn stream_connections_has_ip_transport_discriminates() {
        // Registrant liveness: a WS UE from the same IP as a TLS trunk must
        // not be counted as the trunk's connection.
        let registry = StreamConnections::new();
        registry.register(addr("10.0.0.1:50000"), Transport::WebSocket, ConnectionId(1));
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(registry.has_ip_transport(ip, Transport::WebSocket));
        assert!(!registry.has_ip_transport(ip, Transport::Tls));
        registry.register(addr("10.0.0.1:443"), Transport::Tls, ConnectionId(2));
        assert!(registry.has_ip_transport(ip, Transport::Tls));
    }

    #[test]
    fn stream_connections_unregister_removes_entry() {
        let registry = StreamConnections::new();
        let peer = addr("10.0.0.1:50000");
        registry.register(peer, Transport::Tls, ConnectionId(5));
        registry.unregister(&peer);
        assert!(registry.is_empty());
        assert_eq!(registry.get(&peer), None);
    }

    #[test]
    fn stream_connections_shared_across_threads() {
        use std::thread;
        let registry = StreamConnections::new();
        let mut handles = vec![];
        for i in 0..16u16 {
            let registry = registry.clone();
            handles.push(thread::spawn(move || {
                let peer = addr(&format!("10.0.0.{}:50000", i + 1));
                registry.register(peer, Transport::WebSocket, ConnectionId(i as u64));
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(registry.len(), 16);
        assert_eq!(
            registry.get(&addr("10.0.0.5:50000")),
            Some((Transport::WebSocket, ConnectionId(4))),
        );
    }
}
