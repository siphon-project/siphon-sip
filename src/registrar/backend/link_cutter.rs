//! A TCP relay a test puts between a backend client and a real server, so it
//! can cut the link (every open connection reset, new ones refused) and
//! restore it, the way a server restart or a network blip looks from the
//! client, without touching the server other tests share.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// The relay. Dropping it stops it.
pub(crate) struct LinkCutter {
    address: SocketAddr,
    up: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<JoinHandle<()>>>>,
    acceptor: JoinHandle<()>,
}

impl LinkCutter {
    /// Relay connections to `upstream` (a `host:port`).
    pub(crate) async fn start(upstream: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let address = listener.local_addr().expect("relay address");
        let up = Arc::new(AtomicBool::new(true));
        let connections: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::default();
        let acceptor = tokio::spawn({
            let up = Arc::clone(&up);
            let connections = Arc::clone(&connections);
            async move {
                while let Ok((mut client, _)) = listener.accept().await {
                    if !up.load(Ordering::SeqCst) {
                        // Refused: closed straight away, as a dead server is.
                        drop(client);
                        continue;
                    }
                    let upstream = upstream.clone();
                    let relay = tokio::spawn(async move {
                        if let Ok(mut server) = TcpStream::connect(&upstream).await {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        }
                    });
                    connections.lock().expect("connections").push(relay);
                }
            }
        });
        Self {
            address,
            up,
            connections,
            acceptor,
        }
    }

    /// Where the client should connect instead of the server.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Reset every open connection and refuse new ones.
    pub(crate) fn cut(&self) {
        self.up.store(false, Ordering::SeqCst);
        for relay in self.connections.lock().expect("connections").drain(..) {
            relay.abort();
        }
    }

    /// Accept and relay connections again.
    pub(crate) fn restore(&self) {
        self.up.store(true, Ordering::SeqCst);
    }
}

impl Drop for LinkCutter {
    fn drop(&mut self) {
        self.acceptor.abort();
        self.cut();
    }
}
