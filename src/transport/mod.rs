/// Transport layer — UDP, TCP, TLS, WebSocket, WSS, SCTP.
/// Each transport sends inbound SIP messages to the core via a channel
/// and receives outbound messages via a per-connection sender.
pub mod udp;
pub mod tcp;
pub mod tls;
pub mod ws;
#[cfg(feature = "sctp")]
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

/// Best-effort detection of the host's primary routable local IP for the given
/// address family.
///
/// Uses a UDP "route lookup": bind a wildcard socket, `connect()` it to a
/// documentation-range reference address, and read back the source IP the
/// kernel selected. `connect()` on a UDP socket performs no network I/O — it
/// only sets the default peer and triggers the routing-table lookup — so no
/// packets are sent and the reference address need not be reachable. Returns
/// `None` on a host with no matching route (e.g. loopback-only), so callers can
/// fall back.
///
/// This is what lets an instance bound to `0.0.0.0` / `[::]` with no
/// `advertised_address` emit a routable Via/Contact instead of a loopback
/// placeholder.
pub fn detect_routable_local_ip(ipv6: bool) -> Option<IpAddr> {
    // RFC 5737 TEST-NET-1 / RFC 3849 documentation prefix — never real peers.
    let (bind, reference) = if ipv6 {
        ("[::]:0", "[2001:db8::1]:9")
    } else {
        ("0.0.0.0:0", "192.0.2.1:9")
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(reference).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
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

impl Transport {
    /// Parse a SIP transport scheme token (`"udp"`, `"tcp"`, `"tls"`, `"ws"`,
    /// `"wss"`, `"sctp"`, case-insensitive) into a [`Transport`].  Returns
    /// `None` for an unrecognized scheme.
    pub fn from_scheme(scheme: &str) -> Option<Transport> {
        match scheme.to_ascii_lowercase().as_str() {
            "udp" => Some(Transport::Udp),
            "tcp" => Some(Transport::Tcp),
            "tls" => Some(Transport::Tls),
            "ws" => Some(Transport::WebSocket),
            "wss" => Some(Transport::WebSocketSecure),
            "sctp" => Some(Transport::Sctp),
            _ => None,
        }
    }
}

/// A script-requested egress socket ("force send socket") — the operator
/// equivalent of Kamailio's `force_send_socket()` / OpenSIPS' `$fs`.  Selects
/// which of siphon's *own* configured listeners a relayed / dialed request
/// leaves from, on a multi-homed host.  Resolved from a `send_socket=` string
/// (e.g. `"udp:10.0.0.1:5060"`) against the [`ListenerRegistry`], so it always
/// names a real listener and carries that listener's advertised address for
/// the outgoing Via (so responses come back to the same socket).
///
/// Source-socket selection is transport-specific:
/// - **UDP** pins the exact `(ip, port)` listener socket as the egress
///   ([`OutboundMessage::source_local_addr`] → `udp_by_local`).
/// - **TCP/TLS** bind the egress socket's *source IP* (interface); the source
///   port stays ephemeral, because binding the listen port for an outbound
///   connection collides on the 4-tuple in `TIME_WAIT` (`EADDRNOTAVAIL`).
#[derive(Debug, Clone)]
pub struct SendSocket {
    /// The transport of the selected listener.
    pub transport: Transport,
    /// The listener's bound socket address.
    pub addr: SocketAddr,
    /// The listener's advertised host (from `listen: { advertise: ... }`),
    /// used as the outgoing Via sent-by host when set.
    pub advertise: Option<String>,
}

impl SendSocket {
    /// The Via sent-by `(host, port)` this egress socket should advertise.
    /// Prefers the configured advertised host (external reachability behind
    /// NAT / a load balancer); falls back to the bound IP literal.  The port
    /// is always the listener's bound port so a response reaches this socket.
    pub fn via_sent_by(&self) -> (String, u16) {
        let host = self
            .advertise
            .clone()
            .unwrap_or_else(|| self.addr.ip().to_string());
        (host, self.addr.port())
    }
}

/// Parse a `send_socket=` spec string of the form `"<scheme>:<ip>:<port>"`
/// (e.g. `"udp:10.0.0.1:5060"`, `"tls:[2001:db8::1]:5061"`) into its
/// `(transport, addr)` parts.  Validates *format only* — existence as a real
/// listener is checked separately against the [`ListenerRegistry`].
///
/// Returns a human-readable error string suitable for surfacing to a script
/// author as a `ValueError`.
pub fn parse_send_socket(spec: &str) -> Result<(Transport, SocketAddr), String> {
    let (scheme, addr_part) = spec.split_once(':').ok_or_else(|| {
        format!("send_socket '{spec}' must be '<transport>:<ip>:<port>' (e.g. 'udp:10.0.0.1:5060')")
    })?;
    let transport = Transport::from_scheme(scheme).ok_or_else(|| {
        format!("send_socket '{spec}': unknown transport '{scheme}' (use udp/tcp/tls/ws/wss/sctp)")
    })?;
    let addr: SocketAddr = addr_part
        .parse()
        .map_err(|error| format!("send_socket '{spec}': invalid '<ip>:<port>' address: {error}"))?;
    Ok((transport, addr))
}

/// Registry of every configured listener (`transport` + bound address +
/// advertised host), built once at startup.  Backs `send_socket=` resolution:
/// a script may only egress from a socket siphon is actually listening on, and
/// the advertised host it should put in the outgoing Via comes from here too.
///
/// This is distinct from [`OutboundRouter::udp_by_local`] (which holds only the
/// per-listener UDP *channels*) and from the per-transport `listen_addrs` map
/// (which keeps only the first listener of each transport): multi-homed
/// `send_socket` needs the *full* set across every transport.
#[derive(Debug, Default, Clone)]
pub struct ListenerRegistry {
    entries: Arc<std::collections::HashMap<(Transport, SocketAddr), Option<String>>>,
}

impl ListenerRegistry {
    /// Build from `(transport, bound_addr, advertise)` triples.
    pub fn from_entries(
        entries: impl IntoIterator<Item = (Transport, SocketAddr, Option<String>)>,
    ) -> Self {
        let map = entries
            .into_iter()
            .map(|(transport, addr, advertise)| ((transport, addr), advertise))
            .collect();
        Self { entries: Arc::new(map) }
    }

    /// Resolve a parsed `(transport, addr)` to a [`SendSocket`] iff a listener
    /// with exactly that transport+address is configured.  Returns `None` for
    /// an address siphon is not listening on (the caller should then warn and
    /// fall back to default routing rather than drop the request).
    pub fn resolve(&self, transport: Transport, addr: SocketAddr) -> Option<SendSocket> {
        self.entries
            .get(&(transport, addr))
            .map(|advertise| SendSocket { transport, addr, advertise: advertise.clone() })
    }

    /// Number of registered listeners (diagnostics / tests).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no listeners are registered (test fixtures).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    /// SNI / certificate hostname for an outbound TLS handshake. Only
    /// meaningful when this message must open a *new* outbound TLS connection
    /// via the connection pool (`Transport::Tls`, no reusable connection).
    /// `Some(host)` presents the resolved hostname (RFC 6066 SNI is emitted so
    /// a hostname-vhost peer can route the handshake); `None` falls back to the
    /// destination IP literal (no SNI). Ignored for non-TLS transports and for
    /// TLS connection *reuse* (no handshake occurs).
    pub server_name: Option<String>,
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
    // flume's `SendError<T>` hands the un-sent message back to the caller by
    // design, so the Err variant is as large as `OutboundMessage` itself — the
    // type is fixed by flume's channel contract and can't be boxed without
    // rewrapping every caller. Allow the size lint here.
    #[allow(clippy::result_large_err)]
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

    #[test]
    fn detect_routable_local_ip_never_loopback_or_unspecified() {
        // On a host with a default route this returns the primary egress IP; on a
        // loopback-only host it returns None. It must never return a loopback or
        // unspecified address — that placeholder (127.0.0.1) was the foot-gun this
        // replaced. Guarded on Some() so a CI host without a default route passes.
        if let Some(ip) = detect_routable_local_ip(false) {
            assert!(!ip.is_loopback(), "IPv4 detect returned loopback: {ip}");
            assert!(!ip.is_unspecified(), "IPv4 detect returned unspecified: {ip}");
            assert!(ip.is_ipv4(), "requested IPv4, got {ip}");
        }
        if let Some(ip) = detect_routable_local_ip(true) {
            assert!(!ip.is_loopback(), "IPv6 detect returned loopback: {ip}");
            assert!(!ip.is_unspecified(), "IPv6 detect returned unspecified: {ip}");
        }
    }

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
            server_name: None,
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

    #[test]
    fn transport_from_scheme_roundtrips() {
        assert_eq!(Transport::from_scheme("udp"), Some(Transport::Udp));
        assert_eq!(Transport::from_scheme("TCP"), Some(Transport::Tcp));
        assert_eq!(Transport::from_scheme("Tls"), Some(Transport::Tls));
        assert_eq!(Transport::from_scheme("ws"), Some(Transport::WebSocket));
        assert_eq!(Transport::from_scheme("wss"), Some(Transport::WebSocketSecure));
        assert_eq!(Transport::from_scheme("sctp"), Some(Transport::Sctp));
        assert_eq!(Transport::from_scheme("carrier-pigeon"), None);
    }

    #[test]
    fn parse_send_socket_valid_forms() {
        let (transport, addr) = parse_send_socket("udp:10.0.0.1:5060").unwrap();
        assert_eq!(transport, Transport::Udp);
        assert_eq!(addr, "10.0.0.1:5060".parse().unwrap());

        let (transport, addr) = parse_send_socket("tls:[2001:db8::1]:5061").unwrap();
        assert_eq!(transport, Transport::Tls);
        assert_eq!(addr, "[2001:db8::1]:5061".parse().unwrap());
    }

    #[test]
    fn parse_send_socket_rejects_malformed() {
        assert!(parse_send_socket("10.0.0.1:5060").is_err()); // no scheme
        assert!(parse_send_socket("udp:not-an-addr").is_err()); // bad addr
        assert!(parse_send_socket("udp:10.0.0.1").is_err()); // missing port
        assert!(parse_send_socket("smoke-signal:10.0.0.1:5060").is_err()); // bad scheme
    }

    #[test]
    fn outbound_router_routes_udp_by_source_local_addr() {
        // The UDP egress mechanism `send_socket=` relies on: when a message
        // carries `source_local_addr = Some(addr)` and a per-listener channel
        // is registered for `addr`, it must be delivered to *that* listener's
        // channel — not the default.  A message with no (or an unknown) source
        // falls back to the default channel.
        let default = flume::unbounded::<OutboundMessage>();
        let listener_a = flume::unbounded::<OutboundMessage>();
        let listener_b = flume::unbounded::<OutboundMessage>();
        let addr_a = addr("10.0.0.1:5060");
        let addr_b = addr("192.168.1.1:5060");

        let mut udp_by_local = std::collections::HashMap::new();
        udp_by_local.insert(addr_a, listener_a.0.clone());
        udp_by_local.insert(addr_b, listener_b.0.clone());

        let (dummy, _) = flume::unbounded();
        let router = OutboundRouter {
            udp: default.0.clone(),
            udp_by_local,
            tcp: dummy.clone(),
            tls: dummy.clone(),
            ws: dummy.clone(),
            wss: dummy.clone(),
            sctp: dummy,
        };

        let make = |source: Option<SocketAddr>| OutboundMessage {
            connection_id: ConnectionId(0),
            transport: Transport::Udp,
            destination: addr("203.0.113.1:5060"),
            data: Bytes::from_static(b"PING"),
            source_local_addr: source,
            server_name: None,
        };

        // Pinned to listener A → lands on A's channel.
        router.send(make(Some(addr_a))).unwrap();
        assert_eq!(listener_a.1.try_recv().unwrap().source_local_addr, Some(addr_a));
        assert!(listener_b.1.try_recv().is_err());
        assert!(default.1.try_recv().is_err());

        // Pinned to listener B → lands on B's channel.
        router.send(make(Some(addr_b))).unwrap();
        assert_eq!(listener_b.1.try_recv().unwrap().source_local_addr, Some(addr_b));

        // No source → default channel.
        router.send(make(None)).unwrap();
        assert!(default.1.try_recv().is_ok());

        // Unknown source (not a registered listener) → default channel.
        router.send(make(Some(addr("172.16.0.1:5060")))).unwrap();
        assert!(default.1.try_recv().is_ok());
    }

    #[test]
    fn listener_registry_resolves_only_configured_sockets() {
        let registry = ListenerRegistry::from_entries([
            (Transport::Udp, addr("10.0.0.1:5060"), Some("sip.example.com".to_string())),
            (Transport::Udp, addr("192.168.1.1:5060"), None),
            (Transport::Tcp, addr("10.0.0.1:5060"), None),
        ]);
        assert_eq!(registry.len(), 3);

        // Exact transport+addr match resolves, carrying the advertised host.
        let resolved = registry.resolve(Transport::Udp, addr("10.0.0.1:5060")).unwrap();
        assert_eq!(resolved.transport, Transport::Udp);
        assert_eq!(resolved.addr, addr("10.0.0.1:5060"));
        assert_eq!(resolved.via_sent_by(), ("sip.example.com".to_string(), 5060));

        // No advertise → Via host falls back to the bound IP literal.
        let plain = registry.resolve(Transport::Udp, addr("192.168.1.1:5060")).unwrap();
        assert_eq!(plain.via_sent_by(), ("192.168.1.1".to_string(), 5060));

        // Same address, different transport is a distinct listener.
        assert!(registry.resolve(Transport::Tcp, addr("10.0.0.1:5060")).is_some());
        assert!(registry.resolve(Transport::Tls, addr("10.0.0.1:5060")).is_none());

        // An address siphon isn't listening on does not resolve.
        assert!(registry.resolve(Transport::Udp, addr("172.16.0.1:5060")).is_none());
    }
}
