//! Whether the registrar's persistence backend has been reached, and what
//! follows from it: the `siphon_registrar_backend_up` gauge and, when the
//! operator asked for it, `/admin/ready`.
//!
//! A backend that is down when siphon starts is retried in the background
//! (`server::bootstrap`) rather than given up on, so the node runs on memory
//! alone until it answers. This is the state that says so.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::lifecycle::LifecycleParticipant;

/// The reachability of the registrar backend, shared by the task that connects
/// it and the readiness probe.
#[derive(Debug)]
pub struct BackendStatus {
    required_for_readiness: bool,
    up: AtomicBool,
}

impl BackendStatus {
    /// A backend not reached yet. Publishes `siphon_registrar_backend_up 0`.
    pub fn new(required_for_readiness: bool) -> Self {
        crate::metrics::registrar_backend::set_backend_up(false);
        Self {
            required_for_readiness,
            up: AtomicBool::new(false),
        }
    }

    /// The backend answered: restored, and the writer is in place.
    pub fn mark_up(&self) {
        self.up.store(true, Ordering::Release);
        crate::metrics::registrar_backend::set_backend_up(true);
    }

    /// Whether the backend has been reached.
    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Acquire)
    }
}

/// Not ready until the backend has been reached, when `required_for_readiness`
/// is set; always ready otherwise. The backend holds no sessions, so it takes
/// no part in drain.
impl LifecycleParticipant for BackendStatus {
    fn ready(&self) -> Result<(), String> {
        if !self.required_for_readiness || self.is_up() {
            return Ok(());
        }
        Err("registrar backend not connected".to_string())
    }
    fn set_draining(&self, _draining: bool) {}
    fn outstanding(&self) -> usize {
        0
    }
    fn force(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_required_backend_holds_readiness_until_it_is_up() {
        let status = BackendStatus::new(true);
        assert_eq!(
            status.ready().unwrap_err(),
            "registrar backend not connected"
        );
        status.mark_up();
        assert_eq!(status.ready(), Ok(()));
        assert!(status.is_up());
    }

    #[test]
    fn a_backend_not_required_never_holds_readiness() {
        let status = BackendStatus::new(false);
        assert_eq!(status.ready(), Ok(()));
        assert!(!status.is_up());
    }
}
