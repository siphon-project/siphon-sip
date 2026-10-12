//! The writer task of a pooled outbound TCP connection, and the close of a
//! connection that leaves from a pinned local port.
//!
//! A connection whose caller chose the local port is IPsec: a request toward a
//! UE has to leave from the protected client port, because the SA selector
//! names that port (TS 33.203 §7.1).  Every connection to that UE therefore has
//! the same 4-tuple, and that is what sets it apart:
//!
//! - It is not closed for idleness.  The ports belong to the security
//!   association and so does the connection between them, and the next request
//!   to the UE (a re-INVITE, a BYE) can only go out on this 4-tuple.  Closing
//!   it puts the 4-tuple in TIME-WAIT, and a connect on a 4-tuple in TIME-WAIT
//!   fails with `EADDRNOTAVAIL` unless both ends negotiated TCP timestamps;
//!   `SO_REUSEADDR` only helps the bind.  It ends when the peer closes it, on a
//!   read or write error, or when the socket keepalive or `TCP_USER_TIMEOUT`
//!   gives up on a peer that has gone, which is also how it ends once the
//!   association is deleted and nothing answers on its ports any more.
//! - When this end is first to close, it closes with a reset, so the 4-tuple
//!   is free at once instead of after TIME-WAIT, and the pool offers the slot
//!   again only once the socket is closed.
//!
//! The second point is why the writer lives here.  A socket split in two is
//! closed when both halves are gone, and a write half sends a FIN when it is
//! dropped.  To close such a connection at a moment of its choosing, and
//! without that FIN, the reader takes the writer's half back first:
//! [`PoolWriter::close`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::transport::ConnectionId;

/// Whether a connection bound to `bind_addr` leaves from a local port its
/// caller chose, rather than one the OS picks.
pub(crate) fn pins_local_port(bind_addr: SocketAddr) -> bool {
    bind_addr.port() != 0
}

/// What the writer task held when it ended: its half of the socket and the
/// receiver the pool's senders feed.
type WriterParts = (OwnedWriteHalf, mpsc::Receiver<Bytes>);

/// The writer task of one pooled TCP connection, as its reader holds it.
pub(crate) struct PoolWriter {
    connection_id: ConnectionId,
    destination: SocketAddr,
    pinned: bool,
    /// The running task of a connection from a pinned port.  `None` once it
    /// has ended, and from the start for any other connection, whose task runs
    /// detached.
    task: Option<JoinHandle<WriterParts>>,
    stop: Arc<Notify>,
    parts: Option<WriterParts>,
}

impl PoolWriter {
    /// Start writing what arrives on `write_rx` to `writer`, each write bounded
    /// by `write_timeout`.  The task ends on a write error, on a write that
    /// stalls, and when every sender is gone.
    ///
    /// For a connection from an ephemeral port nothing more happens: the task
    /// runs detached, and its half of the socket and its receiver are dropped
    /// with it, which shuts the socket down for writing and closes the channel.
    /// For a pinned port it hands both back to [`close`](Self::close).
    pub(crate) fn spawn(
        mut writer: OwnedWriteHalf,
        mut write_rx: mpsc::Receiver<Bytes>,
        write_timeout: Duration,
        connection_id: ConnectionId,
        destination: SocketAddr,
        pinned: bool,
    ) -> Self {
        let stop = Arc::new(Notify::new());
        let stopped = Arc::clone(&stop);
        let task = tokio::spawn(async move {
            let serve = async {
                while let Some(data) = write_rx.recv().await {
                    match tokio::time::timeout(write_timeout, writer.write_all(&data)).await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            warn!("pool: TCP write error on {:?}: {}", connection_id, error);
                            break;
                        }
                        Err(_) => {
                            warn!(
                                connection_id = ?connection_id,
                                destination = %destination,
                                timeout = ?write_timeout,
                                "pool: TCP write stalled — peer accepted the connection \
                                 but is not draining it (zero receive window); dropping \
                                 the connection so callers stop queueing behind it"
                            );
                            break;
                        }
                    }
                }
            };
            tokio::select! {
                _ = serve => {}
                _ = stopped.notified() => {}
            }
            (writer, write_rx)
        });
        Self {
            connection_id,
            destination,
            pinned,
            task: pinned.then_some(task),
            stop,
            parts: None,
        }
    }

    /// Resolves once the writer of a connection from a pinned port has given
    /// up, and never for any other connection.
    ///
    /// No request can leave on the connection any more, while its socket still
    /// holds the 4-tuple the replacement needs, so the reader ends with it.
    /// The reader of any other connection stays until the peer closes or the
    /// idle timeout, as it always has.
    pub(crate) async fn gave_up(&mut self) {
        let Some(task) = self.task.as_mut() else {
            return std::future::pending().await;
        };
        self.parts = task.await.ok();
        self.task = None;
        info!(
            "pool: TCP connection {:?} to {} closed, its writer gave up",
            self.connection_id, self.destination
        );
    }

    /// Close the connection whose read half is `reader`.
    ///
    /// A connection from a pinned port is closed before this returns, so the
    /// caller can offer its pool slot again knowing the 4-tuple is free.  The
    /// writer is stopped if it is still running, and its half is let go
    /// without the FIN its drop would send, so that `reader` is the last half
    /// and dropping it is what closes the socket.  When the peer has not
    /// closed first (`peer_closed`), that close is a reset: a FIN would leave
    /// this end in TIME-WAIT, and after the peer's FIN a plain close leaves
    /// nothing behind.
    ///
    /// Returns the writer's receiver, for the caller to drop once the pool no
    /// longer offers the connection: a sender takes a closed channel as leave
    /// to connect again.  `None` for any other connection, whose writer keeps
    /// its receiver until its senders are gone.
    pub(crate) async fn close(
        mut self,
        reader: OwnedReadHalf,
        peer_closed: bool,
    ) -> Option<mpsc::Receiver<Bytes>> {
        if !self.pinned {
            return None;
        }
        if let Some(task) = self.task.take() {
            self.stop.notify_one();
            self.parts = task.await.ok();
        }
        if !peer_closed {
            if let Err(error) =
                socket2::SockRef::from(reader.as_ref()).set_linger(Some(Duration::ZERO))
            {
                warn!(
                    connection_id = ?self.connection_id,
                    destination = %self.destination,
                    "pool: TCP connection from a pinned port could not be set to reset \
                     on close, a reconnect may fail until TIME_WAIT ends: {error}"
                );
            }
        }
        let write_rx = self.parts.take().map(|(writer, write_rx)| {
            writer.forget();
            write_rx
        });
        drop(reader);
        write_rx
    }
}
