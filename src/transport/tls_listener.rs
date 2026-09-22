//! A TLS-terminating [`axum::serve::Listener`], shared by the control plane and
//! the admin API.
//!
//! Lives here rather than beside either caller because both need the same two
//! properties, and getting either wrong is a production failure rather than a
//! style problem:
//!
//! - the handshake runs on a **spawned task per connection**, never inline in
//!   `accept()`. `axum::serve` awaits `accept()` serially, so an inline
//!   handshake lets one peer that connects and then stalls hold up every other
//!   connection on that listener;
//! - the acceptor is a [`SharedTlsAcceptor`], read per connection, so a
//!   certificate replaced under a running process (cert-manager, certbot) is
//!   picked up without a restart.

use std::net::SocketAddr;

use tracing::{debug, warn};

use super::tls::SharedTlsAcceptor;

/// Completed-but-unserved connections allowed to queue. Small on purpose: it is
/// backpressure on the handshake pump, and axum drains it as fast as it can
/// spawn.
const READY_QUEUE: usize = 32;

/// A TLS-terminating [`axum::serve::Listener`].
pub struct TlsListener {
    local_addr: SocketAddr,
    ready: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
}

impl TlsListener {
    /// Bind, and spawn the accept + handshake pump.
    ///
    /// `context` names the caller in this listener's log lines ("control plane",
    /// "admin API"), because a handshake failure is otherwise impossible to
    /// attribute when a node runs both.
    pub async fn bind(
        listen_addr: SocketAddr,
        acceptor: SharedTlsAcceptor,
        context: &'static str,
    ) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        let local_addr = listener.local_addr()?;
        let (ready_tx, ready) = tokio::sync::mpsc::channel(READY_QUEUE);

        tokio::spawn(async move {
            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // A per-connection error (EMFILE, a peer that reset
                        // between SYN and accept) must not end the listener.
                        warn!(%error, "{context}: accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                        continue;
                    }
                };
                // Loaded per connection, so a rotated certificate is served by
                // the next handshake rather than the next restart.
                let acceptor = acceptor.load_full();
                let ready_tx = ready_tx.clone();
                tokio::spawn(async move {
                    let handshake = tokio::time::timeout(
                        super::tls::TLS_HANDSHAKE_TIMEOUT,
                        acceptor.accept(stream),
                    )
                    .await;
                    match handshake {
                        Ok(Ok(stream)) => {
                            let _ = ready_tx.send((stream, peer_addr)).await;
                        }
                        Ok(Err(error)) => {
                            debug!(%peer_addr, %error, "{context}: TLS handshake failed");
                        }
                        Err(_) => {
                            debug!(
                                %peer_addr,
                                timeout = ?super::tls::TLS_HANDSHAKE_TIMEOUT,
                                "{context}: TLS handshake timed out"
                            );
                        }
                    }
                });
            }
        });

        Ok(Self { local_addr, ready })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.ready.recv().await {
                Some(accepted) => return accepted,
                // The pump task is gone, so nothing will ever arrive. The trait
                // has no way to say so; parking here is the honest answer and
                // leaves the process's other listeners running.
                None => std::future::pending::<()>().await,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.local_addr)
    }
}

/// The peer address of a [`TlsListener`] connection, as connect-info.
///
/// A newtype rather than `SocketAddr` because axum implements `Connected` only
/// for a `TcpListener`'s stream, and the orphan rule forbids writing that impl
/// for std's `SocketAddr` against this listener. Callers that need the source
/// address of a TLS connection — the admin API's auto-ban hook — read this.
#[derive(Debug, Clone, Copy)]
pub struct TlsPeer(pub SocketAddr);

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>>
    for TlsPeer
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        TlsPeer(*stream.remote_addr())
    }
}
