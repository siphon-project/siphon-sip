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

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use dashmap::DashMap;
use tokio::sync::Notify;
use tracing::info;

use crate::transport::{ConnectionId, Transport};

/// One live inbound stream connection: whose it is, and how to end it.
struct LiveConnection {
    /// The peer address the connection is served as — the PROXY-declared client
    /// behind a front, the socket's own peer otherwise.
    source: IpAddr,
    transport: Transport,
    /// Signalled once, by [`close_banned_source`]. The connection's own task
    /// waits on it and tears itself down; nothing here touches its socket.
    close: Arc<Notify>,
}

/// Every live inbound stream connection, keyed by its connection id.
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
    /// Register a connection from `source`, served on `transport`.
    pub(crate) fn register(
        connection_id: ConnectionId,
        source: IpAddr,
        transport: Transport,
    ) -> Self {
        let close = Arc::new(Notify::new());
        LIVE_CONNECTIONS.insert(
            connection_id,
            LiveConnection {
                source,
                transport,
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

impl Drop for ConnectionCloser {
    fn drop(&mut self) {
        LIVE_CONNECTIONS.remove(&self.connection_id);
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
        .filter(|entry| entry.value().source == source)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("a test address")
    }

    #[tokio::test]
    async fn a_ban_signals_only_the_banned_source() {
        let banned =
            ConnectionCloser::register(ConnectionId(9001), ip("203.0.113.5"), Transport::Tls);
        let other =
            ConnectionCloser::register(ConnectionId(9002), ip("203.0.113.6"), Transport::Tcp);

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
            ConnectionCloser::register(ConnectionId(9003), ip("203.0.113.7"), Transport::Tcp);
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
                ConnectionCloser::register(*connection_id, ip("203.0.113.10"), Transport::Tcp);
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
