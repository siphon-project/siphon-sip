//! Local sources the pool binds for a registrant UE on an address of its own.
//!
//! A pool-fallback TCP send normally leaves from an ephemeral port: only a
//! P-CSCF protected port is bound exactly (see `stream::pool_tcp_source`). An
//! IMS UE registering over TCP from an address of its own needs the same for
//! its side: TS 24.229 clause 5.1.1.2.2 has its connection "established by the
//! UE, i.e. from the UE's protected client port and the UE's IP address to the
//! P-CSCF's protected server port", and its unprotected initial REGISTER leaves
//! from the plain port its Via names. The registration loop states those
//! sources here on every tick ([`ConnectionPool::reconcile_pinned_sources`]);
//! a send naming one of them as its `source_local_addr` connects from it.
//!
//! The same call closes the connections the UE no longer uses: one from a
//! client port no security association holds any more (a re-authentication
//! rotates the port, TS 33.203 clause 7.4), and every one of an entry that
//! moved or went away. A connection from a pinned port closes with a reset
//! ([`crate::transport::pool_writer`]), so its 4-tuple is free at once.

use super::*;

impl ConnectionPool {
    /// Make `sources` the set of local sources a pool-fallback send may bind,
    /// and close every pooled TCP connection bound from a source in the old or
    /// the new set that `keep` does not name. Returns how many it closed.
    ///
    /// Stated in full by one owner (the registration loop), like
    /// [`set_idle_exempt_destinations`](Self::set_idle_exempt_destinations):
    /// a source left out is released and its connections close.
    pub fn reconcile_pinned_sources(
        &self,
        sources: HashSet<SocketAddr>,
        keep: &HashSet<SocketAddr>,
    ) -> usize {
        let previous = self.pinned_sources.swap(Arc::new(sources));
        let current = self.pinned_sources.load();
        let closing: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|entry| {
                entry.key().transport == Transport::Tcp
                    && entry.key().bind.is_some_and(|bind| {
                        (previous.contains(&bind) || current.contains(&bind))
                            && !keep.contains(&bind)
                    })
            })
            .map(|entry| entry.value().connection_id)
            .collect();
        closing
            .into_iter()
            .filter(|connection_id| {
                crate::transport::disconnect::close_connection(
                    *connection_id,
                    "the registrant UE no longer uses this local source",
                )
            })
            .count()
    }

    /// Whether a pool-fallback send naming `source` binds it.
    pub fn binds_source(&self, source: SocketAddr) -> bool {
        self.pinned_sources.load().contains(&source)
    }

    /// Whether the pooled TCP connection from exactly `source` to
    /// `destination` is open: the one a send pinned to that source reuses.
    pub fn has_live_from(&self, source: SocketAddr, destination: SocketAddr) -> bool {
        let key = PoolKey {
            destination,
            transport: Transport::Tcp,
            bind: Some(source),
            verified_name: None,
        };
        self.connections
            .get(&key)
            .is_some_and(|entry| !entry.sender.is_closed())
    }

    /// How many pooled TCP connections are bound from a source on `ip`, for
    /// the drains-to-zero leak gate.
    pub fn connections_bound_on(&self, ip: std::net::IpAddr) -> usize {
        self.connections
            .iter()
            .filter(|entry| {
                entry.key().transport == Transport::Tcp
                    && entry.key().bind.is_some_and(|bind| bind.ip() == ip)
            })
            .count()
    }
}

/// A pool on loopback with no TLS identity, for tests in other modules.
#[cfg(test)]
impl ConnectionPool {
    pub(crate) fn for_tests(
        connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
        inbound_tx: flume::Sender<InboundMessage>,
    ) -> Self {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let tls = build_outbound_tls_config(None, TlsMethod::default())
            .unwrap_or_else(|error| panic!("an outbound TLS config: {error}"));
        ConnectionPool::new(
            connection_map,
            inbound_tx,
            SocketAddr::from(([127, 0, 0, 1], 5060)),
            None,
            None,
            None,
            tls,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn test_pool() -> (ConnectionPool, flume::Receiver<InboundMessage>) {
        let (inbound_tx, inbound_rx) = flume::unbounded();
        (
            ConnectionPool::for_tests(Arc::new(DashMap::new()), inbound_tx),
            inbound_rx,
        )
    }

    /// A free local port on `ip`, released before returning; `SO_REUSEADDR`
    /// lets the pool bind it afterwards.
    fn free_source(ip: [u8; 4]) -> SocketAddr {
        let reserve = tokio::net::TcpSocket::new_v4().expect("a socket");
        reserve.set_reuseaddr(true).expect("SO_REUSEADDR");
        reserve
            .bind(SocketAddr::from((ip, 0)))
            .expect("a free port");
        reserve.local_addr().expect("its address")
    }

    async fn until(mut condition: impl FnMut() -> bool) -> bool {
        for _ in 0..300 {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        condition()
    }

    #[tokio::test]
    async fn a_released_source_closes_its_connection_and_a_kept_one_stays() {
        let (pool, _inbound) = test_pool();
        let registrar = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let destination = registrar.local_addr().expect("its address");
        let kept = free_source([127, 0, 0, 2]);
        let dropped = free_source([127, 0, 0, 3]);
        let sources: HashSet<SocketAddr> = [kept, dropped].into_iter().collect();

        assert!(!pool.binds_source(kept));
        assert_eq!(pool.reconcile_pinned_sources(sources.clone(), &sources), 0);
        assert!(pool.binds_source(kept) && pool.binds_source(dropped));

        for source in [kept, dropped] {
            pool.send_tcp_from(source, destination, Bytes::from_static(b"\r\n\r\n"))
                .await
                .expect("connected from the pinned source");
        }
        let (_first, from_first) = registrar.accept().await.expect("an accept");
        let (_second, from_second) = registrar.accept().await.expect("an accept");
        let seen: HashSet<SocketAddr> = [from_first, from_second].into_iter().collect();
        assert_eq!(seen, sources, "each connection leaves from its source");
        assert!(pool.has_live_from(kept, destination));
        assert_eq!(pool.connections_bound_on(dropped.ip()), 1);

        // The dropped source leaves the set: its connection closes, the other
        // stays.
        let only_kept: HashSet<SocketAddr> = [kept].into_iter().collect();
        assert_eq!(
            pool.reconcile_pinned_sources(only_kept.clone(), &only_kept),
            1
        );
        assert!(!pool.binds_source(dropped));
        assert!(until(|| pool.connections_bound_on(dropped.ip()) == 0).await);
        assert!(pool.has_live_from(kept, destination));

        // A source still allowed but not kept closes too (a client port no
        // security association holds), yet stays bindable.
        assert_eq!(pool.reconcile_pinned_sources(only_kept, &HashSet::new()), 1);
        assert!(pool.binds_source(kept));
        assert!(until(|| pool.connections_bound_on(kept.ip()) == 0).await);
        assert!(!pool.has_live_from(kept, destination));
    }

    #[tokio::test]
    async fn an_unrelated_source_bound_connection_is_never_closed() {
        let (pool, _inbound) = test_pool();
        let registrar = TcpListener::bind("127.0.0.1:0").await.expect("a listener");
        let destination = registrar.local_addr().expect("its address");
        let protected = free_source([127, 0, 0, 4]);
        pool.send_tcp_from(protected, destination, Bytes::from_static(b"\r\n\r\n"))
            .await
            .expect("connected");
        let _accepted = registrar.accept().await.expect("an accept");

        // Not a pinned source: a P-CSCF protected port, say.
        assert_eq!(
            pool.reconcile_pinned_sources(HashSet::new(), &HashSet::new()),
            0
        );
        assert!(pool.has_live_from(protected, destination));
    }
}
