//! Opening a pooled TCP connection without sending on it.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{evict_if_current, ConnectionPool, PoolKey};
use crate::transport::{ConnectionId, Transport};

impl ConnectionPool {
    /// Open, or find open, the pooled TCP connection from `source` to
    /// `destination` without sending anything, so a caller can commit a
    /// request to TCP only once the connection is known to be there. The
    /// connection is the one a later [`send_tcp_from`](Self::send_tcp_from)
    /// with the same pair reuses; concurrent establishment coalesces as it
    /// does for a send.
    ///
    /// A P-CSCF opens its connection to a UE's protected server port this way
    /// before moving an over-MTU request off UDP: the connect has to leave
    /// from the protected client port to be carried by the security
    /// association, so an unbound reachability probe says nothing.
    pub async fn connect_tcp_from(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> Result<ConnectionId, std::io::Error> {
        let key = PoolKey {
            destination,
            transport: Transport::Tcp,
            bind: Some(source),
            verified_name: None,
        };
        if let Some((connection_id, sender)) = self.pooled(&key) {
            if !sender.is_closed() {
                return Ok(connection_id);
            }
            evict_if_current(&self.connections, &key, connection_id);
        }
        let connect_lock = self
            .connect_locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let result = {
            let _establish_guard = connect_lock.lock().await;
            match self.pooled(&key) {
                Some((connection_id, sender)) if !sender.is_closed() => Ok(connection_id),
                _ => {
                    self.establish_tcp_connection(key.clone(), source, destination, None)
                        .await
                }
            }
        };
        self.connect_locks
            .remove_if(&key, |_, lock| Arc::strong_count(lock) <= 2);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use dashmap::DashMap;

    fn pool() -> ConnectionPool {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        ConnectionPool::new(
            Arc::new(DashMap::new()),
            flume::unbounded().0,
            "127.0.0.1:5060".parse().expect("an address"),
            None,
            None,
            None,
            super::super::build_outbound_tls_config(None, crate::config::TlsMethod::default())
                .expect("outbound tls config"),
        )
    }

    fn free_source() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("a free port")
            .local_addr()
            .expect("bound")
    }

    /// A bare connect opens the connection from `source` that the next send
    /// with the same pair reuses, and a second connect finds it open.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_bare_connect_is_the_connection_the_next_send_reuses() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a listener");
        let destination = listener.local_addr().expect("bound");
        // The accepted stream comes back with its peer and is held to the end:
        // dropped, the pool's reader would see EOF and evict the connection,
        // and the next connect or send could land on a new one.
        let accepted = tokio::spawn(async move { listener.accept().await });
        let pool = pool();
        let source = free_source();

        let opened = pool
            .connect_tcp_from(source, destination)
            .await
            .expect("the connection opens");
        let (_held, peer) = accepted.await.expect("the accept task").expect("accepted");
        assert_eq!(peer, source, "opened from the requested source");
        assert_eq!(
            pool.connect_tcp_from(source, destination)
                .await
                .expect("found open"),
            opened
        );
        let sent = pool
            .send_tcp_from(
                source,
                destination,
                Bytes::from_static(b"OPTIONS sip:x SIP/2.0\r\n\r\n"),
            )
            .await
            .expect("sent");
        assert_eq!(sent, opened, "the send reuses it");
        assert_eq!(pool.active_connections(), 1);
    }

    /// A refused connect is an error and leaves nothing in the pool.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_connect_is_an_error_and_pools_nothing() {
        let pool = pool();
        let destination = free_source();
        assert!(pool
            .connect_tcp_from(free_source(), destination)
            .await
            .is_err());
        assert_eq!(pool.active_connections(), 0);
    }
}
