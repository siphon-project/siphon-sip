//! Closing the stream connections a banned source already holds open.
//!
//! Every ban check siphon had ran **per connection**: the ACL
//! ([`crate::transport::acl::TransportAcl::is_allowed`]) at accept, and
//! [`crate::security::is_source_banned`] once the handshake completed. A source
//! that never reconnects therefore never meets either again, so the connection
//! it already has outlives the ban that was raised because of it. Observed in
//! production over TLS: REGISTERs with rejected credentials kept reaching the
//! script for two minutes after the ban, each rejection sliding the expiry
//! further out, while every other client behind that address was refused at
//! accept for the whole time; eight minutes in, a REGISTER carrying the right
//! password came up that same connection and its binding was stored, with the
//! source still banned. UDP never had the gap — it runs the ACL per datagram.
//!
//! So every accepted stream connection registers here for its lifetime —
//! [`crate::transport::stream::serve_sip_stream`] covers TCP, TLS and the SIP
//! arm of the mux, [`crate::transport::ws::handle_connection`] covers WS, WSS
//! and the mux's WebSocket arm — and [`AutoBanStore`] calls
//! [`close_banned_source`] the moment it raises a ban, which signals each of
//! that address's connections to tear itself down.
//!
//! [`AutoBanStore`]: crate::security::AutoBanStore
//!
//! **Why the registration carries its own close handle** rather than reusing
//! [`crate::transport::StreamConnections`]: that registry maps an address to a
//! [`ConnectionId`], which is a routing key and not a way to reach the task, and
//! it also holds the outbound pool's connections — which siphon opened and which
//! a ban on the far end says nothing about. This one holds only connections a
//! peer opened to us, each with the handle that ends it.
//!
//! The address registered is the one the connection is served as, so behind a
//! connection-terminating front it is the client address the PROXY header
//! declared ([`crate::transport::proxy_protocol::admit_proxied_client`] runs in
//! the accept loop, before any of this): a ban matches the client that earned
//! it, not the front every client shares.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use tokio::sync::Notify;
use tracing::info;

use crate::transport::{ConnectionId, Transport};

/// One live stream connection: whose it is, and how to end it.
struct LiveConnection {
    /// The peer address the connection is served as — the PROXY-declared client
    /// behind a front, the socket's own peer otherwise.
    peer: SocketAddr,
    /// Whether the peer opened it ([`ConnectionCloser::register`]) rather than
    /// siphon ([`ConnectionCloser::register_outbound`]). Only the former is a
    /// ban's business.
    inbound: bool,
    transport: Transport,
    /// The local port siphon bound a connection it opened to, when it pinned
    /// one: a P-CSCF's protected client port (TS 33.203 clause 7.1).
    local_port: Option<u16>,
    /// Signalled once, by [`close_banned_source`]. The connection's own task
    /// waits on it and tears itself down; nothing here touches its socket.
    close: Arc<Notify>,
}

/// Every live stream connection, keyed by its connection id: the ones peers
/// opened to us, and the outbound pool's own (which a ban never touches, see
/// [`close_peer`]).
///
/// Written once per accepted connection and once more when it ends (never per
/// message), and read only when a ban is *newly* raised — so the linear scan in
/// [`close_banned_source`] is paid on the ban transition, not on the datapath.
static LIVE_CONNECTIONS: LazyLock<DashMap<ConnectionId, LiveConnection>> =
    LazyLock::new(DashMap::new);

/// A live connection's entry in [`LIVE_CONNECTIONS`], and its way of hearing
/// that its source has just been banned.
///
/// Registered for the whole life of the connection: the entry is removed when
/// this value drops, so a connection that ends normally leaves nothing behind
/// even on the cancellation path (where an explicit removal next to the cleanup
/// would be skipped).
pub(crate) struct ConnectionCloser {
    connection_id: ConnectionId,
    close: Arc<Notify>,
}

impl ConnectionCloser {
    /// Register a connection `peer` opened to us, served on `transport`.
    pub(crate) fn register(
        connection_id: ConnectionId,
        peer: SocketAddr,
        transport: Transport,
    ) -> Self {
        Self::register_with(connection_id, peer, transport, true, None)
    }

    /// Register a connection siphon opened to `peer` (the outbound pool's)
    /// from `local_port` when it pinned one, so it can be ended from outside
    /// its task by [`close_peer`], [`close_peer_from`] and
    /// [`close_connection`]. A ban never closes it.
    pub(crate) fn register_outbound(
        connection_id: ConnectionId,
        peer: SocketAddr,
        transport: Transport,
        local_port: Option<u16>,
    ) -> Self {
        Self::register_with(connection_id, peer, transport, false, local_port)
    }

    fn register_with(
        connection_id: ConnectionId,
        peer: SocketAddr,
        transport: Transport,
        inbound: bool,
        local_port: Option<u16>,
    ) -> Self {
        let close = Arc::new(Notify::new());
        LIVE_CONNECTIONS.insert(
            connection_id,
            LiveConnection {
                peer,
                inbound,
                transport,
                local_port,
                close: Arc::clone(&close),
            },
        );
        Self {
            connection_id,
            close,
        }
    }

    /// Resolves once this connection's source has been banned.
    ///
    /// Select on it for the life of the connection. The signal is stored rather
    /// than broadcast ([`Notify::notify_one`]), so a ban raised in the window
    /// between registering and reaching the wait is still delivered.
    pub(crate) async fn closed(&self) {
        self.close.notified().await;
    }
}

/// Woken each time a connection leaves [`LIVE_CONNECTIONS`], for
/// [`peer_closed_within`].
static CONNECTION_LEFT: LazyLock<Notify> = LazyLock::new(Notify::new);

impl Drop for ConnectionCloser {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.remove(&self.connection_id);
        CONNECTION_LEFT.notify_waiters();
    }
}

/// Signal every live inbound stream connection held by `source` to close,
/// because `source` has just been banned for `reason`. Returns how many were
/// signalled.
///
/// Called from the ban transition itself, so it covers every path that raises
/// one. Non-blocking and callable from any thread: it wakes each connection's
/// own task, which closes its socket and runs its ordinary cleanup.
pub(crate) fn close_banned_source(source: IpAddr, reason: &str) -> usize {
    // Collected before anything is signalled: the shard guards an iterator holds
    // must not be live while a woken connection's cleanup removes its own entry.
    let held: Vec<(ConnectionId, Transport, Arc<Notify>)> = LIVE_CONNECTIONS
        .iter()
        .filter(|entry| entry.value().inbound && entry.value().peer.ip() == source)
        .map(|entry| {
            (
                *entry.key(),
                entry.value().transport,
                Arc::clone(&entry.value().close),
            )
        })
        .collect();

    for (connection_id, transport, close) in &held {
        close.notify_one();
        info!(
            source = %source,
            transport = %transport,
            connection_id = ?connection_id,
            reason,
            "auto-ban: closing a connection the banned source already had open"
        );
    }
    held.len()
}

/// Signal every live stream connection with `peer`, the exact address and
/// port, to close because `reason`, whichever end opened it. Returns how many
/// were signalled.
///
/// For a P-CSCF deleting a UE's security associations: the connections between
/// the protected ports and the UE's (3GPP TS 33.203 clause 7.1) are carried by
/// them and are of no use without them, and one siphon opened is otherwise kept
/// until the peer closes it or keepalive gives up (see
/// [`crate::transport::pool_writer`]), retransmitting into an association that
/// is gone, toward an address the access network may have given to another UE.
/// A connection siphon opened from a pinned port closes with a reset.
pub(crate) fn close_peer(peer: SocketAddr, reason: &str) -> usize {
    close_matching(peer, None, reason)
}

/// [`close_peer`] for only the connections siphon opened to `peer` from the
/// pinned local port `local_port`: a P-CSCF deleting a UE's set whose
/// protected client port is its own, while a newer set keeps the UE's
/// protected server port and its own connection to it from another port_pc
/// (TS 33.203 clause 7.4.0).
pub(crate) fn close_peer_from(peer: SocketAddr, local_port: u16, reason: &str) -> usize {
    close_matching(peer, Some(local_port), reason)
}

/// Whether `connection` is with `peer`, and from `local_port` when one is
/// given.
fn matches(connection: &LiveConnection, peer: SocketAddr, local_port: Option<u16>) -> bool {
    connection.peer == peer && local_port.is_none_or(|port| connection.local_port == Some(port))
}

fn close_matching(peer: SocketAddr, local_port: Option<u16>, reason: &str) -> usize {
    let held: Vec<(ConnectionId, Transport, Arc<Notify>)> = LIVE_CONNECTIONS
        .iter()
        .filter(|entry| matches(entry.value(), peer, local_port))
        .map(|entry| {
            (
                *entry.key(),
                entry.value().transport,
                Arc::clone(&entry.value().close),
            )
        })
        .collect();
    for (connection_id, transport, close) in &held {
        close.notify_one();
        info!(
            peer = %peer,
            transport = %transport,
            connection_id = ?connection_id,
            reason,
            "closing a connection"
        );
    }
    held.len()
}

/// Wait until no live stream connection with `peer` is left, for at most
/// `bound`. Returns whether none is.
///
/// A connection [`close_peer`] signalled tears itself down in its own task and
/// leaves [`LIVE_CONNECTIONS`] only once its socket is closed, so this is how a
/// caller orders something after that close: a P-CSCF deleting the security
/// associations a connection ran over, whose FIN would otherwise leave in
/// plaintext on the protected port. Bounded, so a connection whose teardown
/// stalls holds the caller up for `bound` and no longer.
pub(crate) async fn peer_closed_within(peer: SocketAddr, bound: std::time::Duration) -> bool {
    closed_within(peer, None, bound).await
}

/// [`peer_closed_within`] for the connections [`close_peer_from`] signals.
pub(crate) async fn peer_closed_from_within(
    peer: SocketAddr,
    local_port: u16,
    bound: std::time::Duration,
) -> bool {
    closed_within(peer, Some(local_port), bound).await
}

async fn closed_within(
    peer: SocketAddr,
    local_port: Option<u16>,
    bound: std::time::Duration,
) -> bool {
    let open = || {
        LIVE_CONNECTIONS
            .iter()
            .any(|entry| matches(entry.value(), peer, local_port))
    };
    tokio::time::timeout(bound, async {
        loop {
            // Armed before the check, so a connection leaving in between
            // still wakes this.
            let left = CONNECTION_LEFT.notified();
            tokio::pin!(left);
            left.as_mut().enable();
            if !open() {
                return;
            }
            left.await;
        }
    })
    .await
    .is_ok()
}

/// Signal one live inbound stream connection to close because `reason`: its
/// peer stopped answering CRLF keep-alives (RFC 5626 §4.4.1). Returns whether
/// the connection was live.
///
/// The way to end a connection from outside its task. Its sender in the
/// connection map is not: the read half holds a clone of it (for the pongs it
/// writes), so dropping the map's copy leaves the channel, the socket and the
/// registrar's binding up until the 300 s idle timeout. This wakes the task,
/// which closes the socket and runs its ordinary cleanup, the flow-failure
/// report to the registrar (RFC 5626 §4.2.2) included.
pub(crate) fn close_connection(connection_id: ConnectionId, reason: &str) -> bool {
    let Some(close) = LIVE_CONNECTIONS
        .get(&connection_id)
        .map(|entry| Arc::clone(&entry.value().close))
    else {
        return false;
    };
    close.notify_one();
    info!(connection_id = ?connection_id, reason, "closing a connection");
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("a test address")
    }

    fn peer(value: &str) -> SocketAddr {
        SocketAddr::new(ip(value), 5060)
    }

    /// `close_peer` ends every connection with that exact address and port,
    /// inbound or outbound, and nothing on another port of the same host.
    #[tokio::test]
    async fn closing_a_peer_signals_its_connections_in_both_directions_only() {
        let accepted = ConnectionCloser::register(
            ConnectionId(9201),
            "198.51.100.21:6100".parse().expect("an address"),
            Transport::Tcp,
        );
        let opened = ConnectionCloser::register_outbound(
            ConnectionId(9202),
            "198.51.100.21:6100".parse().expect("an address"),
            Transport::Tcp,
            None,
        );
        let other_port = ConnectionCloser::register_outbound(
            ConnectionId(9203),
            "198.51.100.21:6101".parse().expect("an address"),
            Transport::Tcp,
            None,
        );

        assert_eq!(
            close_peer(
                "198.51.100.21:6100".parse().expect("an address"),
                "a test signal"
            ),
            2
        );
        for closer in [&accepted, &opened] {
            tokio::time::timeout(std::time::Duration::from_secs(5), closer.closed())
                .await
                .expect("a connection with the peer must be signalled");
        }
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), other_port.closed())
                .await
                .is_err(),
            "a connection to another port of the host must be left alone"
        );
    }

    /// `close_peer_from` ends only the connections siphon opened to the peer
    /// from that pinned local port, and waiting for them ignores the others.
    #[tokio::test]
    async fn closing_a_peer_from_one_local_port_leaves_the_others() {
        let peer: SocketAddr = "198.51.100.22:6101".parse().expect("an address");
        let accepted = ConnectionCloser::register(ConnectionId(9211), peer, Transport::Tcp);
        let from_old = ConnectionCloser::register_outbound(
            ConnectionId(9212),
            peer,
            Transport::Tcp,
            Some(5064),
        );
        let from_new = ConnectionCloser::register_outbound(
            ConnectionId(9213),
            peer,
            Transport::Tcp,
            Some(5068),
        );

        assert_eq!(close_peer_from(peer, 5064, "a test signal"), 1);
        tokio::time::timeout(std::time::Duration::from_secs(5), from_old.closed())
            .await
            .expect("the connection from that port must be signalled");
        drop(from_old);
        assert!(peer_closed_from_within(peer, 5064, std::time::Duration::from_millis(50)).await);
        assert!(!peer_closed_within(peer, std::time::Duration::from_millis(10)).await);
        for kept in [&accepted, &from_new] {
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(50), kept.closed())
                    .await
                    .is_err(),
                "a connection from another port must be left alone"
            );
        }
    }

    /// A ban is about connections the banned source opened; one siphon opened
    /// to that host is not closed by it.
    #[tokio::test]
    async fn a_ban_leaves_outbound_connections_alone() {
        let opened = ConnectionCloser::register_outbound(
            ConnectionId(9301),
            peer("203.0.113.31"),
            Transport::Tcp,
            None,
        );
        assert_eq!(close_banned_source(ip("203.0.113.31"), "a test signal"), 0);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), opened.closed())
                .await
                .is_err(),
            "an outbound connection must not be closed by a ban"
        );
    }

    #[tokio::test]
    async fn closing_one_connection_signals_that_one_alone() {
        let closed =
            ConnectionCloser::register(ConnectionId(9101), peer("203.0.113.15"), Transport::Tls);
        let kept =
            ConnectionCloser::register(ConnectionId(9102), peer("203.0.113.15"), Transport::Tls);

        assert!(close_connection(ConnectionId(9101), "a test signal"));
        tokio::time::timeout(std::time::Duration::from_secs(5), closed.closed())
            .await
            .expect("the named connection must be signalled");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), kept.closed())
                .await
                .is_err(),
            "another connection from the same address must be left alone"
        );
        assert!(!close_connection(ConnectionId(9199), "a test signal"));
    }

    #[tokio::test]
    async fn a_ban_signals_only_the_banned_source() {
        let banned =
            ConnectionCloser::register(ConnectionId(9001), peer("203.0.113.5"), Transport::Tls);
        let other =
            ConnectionCloser::register(ConnectionId(9002), peer("203.0.113.6"), Transport::Tcp);

        assert_eq!(close_banned_source(ip("203.0.113.5"), "a test signal"), 1);

        tokio::time::timeout(std::time::Duration::from_secs(5), banned.closed())
            .await
            .expect("the banned source's connection must be signalled");
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), other.closed())
                .await
                .is_err(),
            "a connection from another address must be left alone"
        );
    }

    /// The signal is stored, so a connection banned before it reaches its wait
    /// still hears it — otherwise the window between registering and selecting
    /// would let a connection survive the ban that named it.
    #[tokio::test]
    async fn a_ban_raised_before_the_wait_is_still_delivered() {
        let closer =
            ConnectionCloser::register(ConnectionId(9003), peer("203.0.113.7"), Transport::Tcp);
        assert_eq!(close_banned_source(ip("203.0.113.7"), "a test signal"), 1);
        tokio::time::timeout(std::time::Duration::from_secs(5), closer.closed())
            .await
            .expect("a ban raised before the wait must still be delivered");
    }

    #[test]
    fn an_unknown_source_signals_nothing() {
        assert_eq!(close_banned_source(ip("203.0.113.8"), "a test signal"), 0);
    }

    /// Every registration is evicted when its connection ends, so the registry
    /// cannot grow one row per connection.
    ///
    /// Keyed on this test's own ids rather than on `len()`: the registry is
    /// process-wide and the other tests in this binary hold live connections in
    /// it while this one runs, so a total count is not a usable instrument here.
    #[test]
    fn every_registration_is_evicted_when_its_connection_ends() {
        let ids: Vec<ConnectionId> = (0..1_000)
            .map(|index| ConnectionId(9_000_000 + index))
            .collect();
        for connection_id in &ids {
            let closer =
                ConnectionCloser::register(*connection_id, peer("203.0.113.10"), Transport::Tcp);
            assert!(LIVE_CONNECTIONS.contains_key(connection_id));
            drop(closer);
            assert!(!LIVE_CONNECTIONS.contains_key(connection_id));
        }
        assert!(
            ids.iter()
                .all(|connection_id| !LIVE_CONNECTIONS.contains_key(connection_id)),
            "a connection that ended left its registration behind"
        );
    }
}
