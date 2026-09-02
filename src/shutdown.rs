//! Graceful shutdown coordinator.
//!
//! On SIGTERM/SIGINT:
//! 1. Set shutdown flag — stop accepting new connections/transactions.
//! 2. Wait up to `timeout` for in-flight transactions to complete.
//! 3. After timeout: forcibly terminate remaining transactions with 503.
//!
//! Components subscribe to the shutdown signal via `ShutdownSignal::subscribe()`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{broadcast, watch};
use tracing::{debug, info, warn};

/// The shutdown coordinator. Shared across all components.
#[derive(Debug, Clone)]
pub struct ShutdownCoordinator {
    inner: Arc<ShutdownInner>,
}

#[derive(Debug)]
struct ShutdownInner {
    /// True once shutdown has been initiated.
    shutting_down: AtomicBool,
    /// Watch channel: components poll this to know when shutdown is triggered.
    notify_tx: watch::Sender<bool>,
    /// Broadcast channel: components receive this to begin draining.
    broadcast_tx: broadcast::Sender<ShutdownPhase>,
    /// How long to wait for graceful drain before forcing.
    timeout: Duration,
}

/// Shutdown phases communicated to components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownPhase {
    /// Stop accepting new work. Drain existing transactions.
    Draining,
    /// Timeout reached. Forcibly terminate everything.
    ForceTerminate,
}

/// A handle that components use to listen for shutdown signals.
#[derive(Debug)]
pub struct ShutdownSignal {
    watch_rx: watch::Receiver<bool>,
    broadcast_rx: broadcast::Receiver<ShutdownPhase>,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator with the given drain timeout.
    pub fn new(timeout: Duration) -> Self {
        let (notify_tx, _notify_rx) = watch::channel(false);
        let (broadcast_tx, _broadcast_rx) = broadcast::channel(16);

        Self {
            inner: Arc::new(ShutdownInner {
                shutting_down: AtomicBool::new(false),
                notify_tx,
                broadcast_tx,
                timeout,
            }),
        }
    }

    /// Subscribe to shutdown signals. Returns a handle for the calling component.
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            watch_rx: self.inner.notify_tx.subscribe(),
            broadcast_rx: self.inner.broadcast_tx.subscribe(),
        }
    }

    /// Check if shutdown has been initiated.
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::Relaxed)
    }

    /// Initiate graceful shutdown.
    ///
    /// 1. Sets the shutdown flag.
    /// 2. Sends `Draining` to all subscribers.
    /// 3. Waits for `timeout`.
    /// 4. Sends `ForceTerminate` to all subscribers.
    pub async fn shutdown(&self) {
        if self.inner.shutting_down.swap(true, Ordering::SeqCst) {
            debug!("Shutdown already in progress");
            return;
        }

        info!(
            "Graceful shutdown initiated — draining for {:?}",
            self.inner.timeout
        );

        // Notify via watch (polled by accept loops)
        let _ = self.inner.notify_tx.send(true);

        // Broadcast drain phase
        let _ = self.inner.broadcast_tx.send(ShutdownPhase::Draining);

        // Wait for drain timeout
        tokio::time::sleep(self.inner.timeout).await;

        // Force terminate
        warn!("Shutdown timeout reached — force-terminating remaining transactions");
        let _ = self.inner.broadcast_tx.send(ShutdownPhase::ForceTerminate);
    }

    /// Get the configured drain timeout.
    pub fn timeout(&self) -> Duration {
        self.inner.timeout
    }
}

impl ShutdownSignal {
    /// Wait until shutdown is initiated. Returns immediately if already shutting down.
    pub async fn wait_for_shutdown(&mut self) {
        // Watch returns when value changes to true
        let _ = self.watch_rx.wait_for(|&v| v).await;
    }

    /// Receive the next shutdown phase.
    pub async fn recv_phase(&mut self) -> Option<ShutdownPhase> {
        self.broadcast_rx.recv().await.ok()
    }

    /// Check if shutdown has been signalled (non-blocking).
    pub fn is_shutdown(&self) -> bool {
        *self.watch_rx.borrow()
    }
}

/// Install OS signal handlers and return when SIGTERM or SIGINT is received.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                warn!("Failed to install SIGTERM handler: {error}");
                // Fall back to ctrl_c only
                if let Err(error) = tokio::signal::ctrl_c().await {
                    warn!("Ctrl-C handler also failed: {error}");
                }
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(signal) => signal,
            Err(error) => {
                warn!("Failed to install SIGINT handler: {error}");
                // Wait on SIGTERM only
                sigterm.recv().await;
                info!("Received SIGTERM");
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            warn!("Ctrl-C handler failed: {error}");
        } else {
            info!("Received Ctrl-C");
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinator_initial_state() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(30));
        assert!(!coord.is_shutting_down());
        assert_eq!(coord.timeout(), Duration::from_secs(30));
    }

    #[test]
    fn subscribe_returns_signal() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(5));
        let signal = coord.subscribe();
        assert!(!signal.is_shutdown());
    }

    #[tokio::test]
    async fn shutdown_sets_flag_and_notifies() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(50));
        let mut signal = coord.subscribe();

        assert!(!coord.is_shutting_down());

        // Spawn shutdown in background
        let coord_clone = coord.clone();
        tokio::spawn(async move {
            coord_clone.shutdown().await;
        });

        // Wait for shutdown signal
        signal.wait_for_shutdown().await;
        assert!(coord.is_shutting_down());
        assert!(signal.is_shutdown());
    }

    #[tokio::test]
    async fn shutdown_phases_received() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(10));
        let mut signal = coord.subscribe();

        let coord_clone = coord.clone();
        tokio::spawn(async move {
            coord_clone.shutdown().await;
        });

        // Should receive Draining first
        let phase = signal.recv_phase().await.unwrap();
        assert_eq!(phase, ShutdownPhase::Draining);

        // Then ForceTerminate after timeout
        let phase = signal.recv_phase().await.unwrap();
        assert_eq!(phase, ShutdownPhase::ForceTerminate);
    }

    #[tokio::test]
    async fn double_shutdown_is_idempotent() {
        let coord = ShutdownCoordinator::new(Duration::from_millis(10));

        let coord1 = coord.clone();
        let coord2 = coord.clone();

        let handle1 = tokio::spawn(async move { coord1.shutdown().await });
        let handle2 = tokio::spawn(async move { coord2.shutdown().await });

        let _ = tokio::join!(handle1, handle2);
        assert!(coord.is_shutting_down());
    }

    #[test]
    fn clone_shares_state() {
        let coord = ShutdownCoordinator::new(Duration::from_secs(30));
        let coord2 = coord.clone();

        coord.inner.shutting_down.store(true, Ordering::SeqCst);
        assert!(coord2.is_shutting_down());
    }
}
