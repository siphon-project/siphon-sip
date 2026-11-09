//! Lifecycle participants: how a Rust addon takes part in readiness, drain and
//! shutdown.
//!
//! siphon's own readiness is "not draining", and its own shutdown waits for SIP
//! transactions and B2BUA calls. An addon that owns long-lived state of its own
//! (sessions over a protocol siphon does not speak, sockets it binds itself, an
//! upstream peer it depends on) is invisible to both. Registering a
//! [`LifecycleParticipant`] with
//! [`SiphonServer::register_lifecycle`](crate::SiphonServer::register_lifecycle)
//! makes it visible:
//!
//! - `GET /admin/ready` answers 503 with the participant's reason while
//!   [`ready`](LifecycleParticipant::ready) returns `Err`.
//! - `POST` / `DELETE /admin/drain` call
//!   [`set_draining`](LifecycleParticipant::set_draining) on every participant.
//! - On SIGTERM the shutdown sequence calls `set_draining(true)`, then holds the
//!   exit while transactions, calls and the participants'
//!   [`outstanding`](LifecycleParticipant::outstanding) are above zero, and when
//!   `server.drain_secs` runs out calls [`force`](LifecycleParticipant::force) on
//!   every participant before exiting.
//!
//! With no participant registered, none of this changes anything.

use std::sync::{Arc, Mutex};

/// A Rust component that takes part in siphon's readiness, drain and shutdown.
///
/// Every method is called from async tasks (the admin handlers, the shutdown
/// sequence) and **must return promptly without blocking and without attaching
/// to the Python interpreter**: read an atomic or take a short lock, and spawn
/// anything slower onto your own task. Never call into Python from here, and
/// never hold one of your own locks across a call that re-enters siphon.
pub trait LifecycleParticipant: Send + Sync + 'static {
    /// `Ok(())` when the component can take traffic, `Err(reason)` when it
    /// cannot (a socket not bound yet, no upstream peer up, a licence refused).
    /// The reason is returned to the probe as-is, so keep it short and free of
    /// secrets. Polled on every `/admin/ready` request.
    fn ready(&self) -> Result<(), String>;

    /// Enter (`true`) or leave (`false`) drain: stop accepting new work and
    /// start winding existing work down (send redirects to clients, delete
    /// sessions). Called on `POST` / `DELETE /admin/drain` and once, with
    /// `true`, when the shutdown signal arrives. Must be idempotent.
    fn set_draining(&self, draining: bool);

    /// How much work is still held: sessions not yet gone. Shutdown waits while
    /// the sum over all participants, plus siphon's own transactions and calls,
    /// is above zero. Polled twice a second during the drain.
    fn outstanding(&self) -> usize;

    /// The drain deadline passed with [`outstanding`](Self::outstanding) still
    /// above zero: tear down what is left now. Called once per participant,
    /// immediately before the process exits.
    fn force(&self);
}

/// The registered participants, shared by the admin handlers and the shutdown
/// sequence through [`DrainState`](crate::dispatcher::DrainState).
#[derive(Default)]
pub struct Participants {
    registered: Mutex<Vec<Arc<dyn LifecycleParticipant>>>,
}

impl Participants {
    /// Add a participant. Registration order is the order `ready` is polled in.
    pub fn register(&self, participant: Arc<dyn LifecycleParticipant>) {
        if let Ok(mut registered) = self.registered.lock() {
            registered.push(participant);
        }
    }

    /// Clone of the list, so no lock is held while a callback runs.
    fn snapshot(&self) -> Vec<Arc<dyn LifecycleParticipant>> {
        self.registered
            .lock()
            .map(|registered| registered.clone())
            .unwrap_or_default()
    }

    /// The first registered participant's refusal, if any is not ready.
    pub fn not_ready_reason(&self) -> Option<String> {
        self.snapshot()
            .iter()
            .find_map(|participant| participant.ready().err())
    }

    /// Forward a drain change to every participant.
    pub fn set_draining(&self, draining: bool) {
        for participant in self.snapshot() {
            participant.set_draining(draining);
        }
    }

    /// Sum of every participant's outstanding work.
    pub fn outstanding(&self) -> usize {
        self.snapshot()
            .iter()
            .map(|participant| participant.outstanding())
            .fold(0, usize::saturating_add)
    }

    /// Force every participant.
    pub fn force(&self) {
        for participant in self.snapshot() {
            participant.force();
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::LifecycleParticipant;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A participant whose answers the test sets and whose calls it counts.
    pub(crate) struct FakeParticipant {
        pub(crate) not_ready: Mutex<Option<String>>,
        pub(crate) draining: AtomicBool,
        pub(crate) draining_calls: AtomicUsize,
        pub(crate) outstanding: AtomicUsize,
        pub(crate) forced: AtomicUsize,
    }

    impl FakeParticipant {
        pub(crate) fn with_outstanding(outstanding: usize) -> Arc<Self> {
            Arc::new(Self {
                not_ready: Mutex::new(None),
                draining: AtomicBool::new(false),
                draining_calls: AtomicUsize::new(0),
                outstanding: AtomicUsize::new(outstanding),
                forced: AtomicUsize::new(0),
            })
        }

        pub(crate) fn refusing(reason: &str) -> Arc<Self> {
            let participant = Self::with_outstanding(0);
            if let Ok(mut slot) = participant.not_ready.lock() {
                *slot = Some(reason.to_owned());
            }
            participant
        }
    }

    impl LifecycleParticipant for FakeParticipant {
        fn ready(&self) -> Result<(), String> {
            match self.not_ready.lock().ok().and_then(|slot| slot.clone()) {
                Some(reason) => Err(reason),
                None => Ok(()),
            }
        }
        fn set_draining(&self, draining: bool) {
            self.draining.store(draining, Ordering::SeqCst);
            self.draining_calls.fetch_add(1, Ordering::SeqCst);
        }
        fn outstanding(&self) -> usize {
            self.outstanding.load(Ordering::SeqCst)
        }
        fn force(&self) {
            self.forced.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::FakeParticipant;
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn no_participants_is_ready_idle_and_inert() {
        let participants = Participants::default();
        assert_eq!(participants.not_ready_reason(), None);
        assert_eq!(participants.outstanding(), 0);
        participants.set_draining(true);
        participants.force();
    }

    #[test]
    fn first_refusal_wins_in_registration_order() {
        let participants = Participants::default();
        participants.register(FakeParticipant::with_outstanding(0));
        participants.register(FakeParticipant::refusing("no peer up"));
        participants.register(FakeParticipant::refusing("licence refused"));
        assert_eq!(
            participants.not_ready_reason().as_deref(),
            Some("no peer up")
        );
    }

    #[test]
    fn outstanding_sums_and_calls_reach_every_participant() {
        let participants = Participants::default();
        let first = FakeParticipant::with_outstanding(2);
        let second = FakeParticipant::with_outstanding(3);
        participants.register(first.clone());
        participants.register(second.clone());
        assert_eq!(participants.outstanding(), 5);
        participants.set_draining(true);
        participants.set_draining(false);
        participants.force();
        for participant in [first, second] {
            assert_eq!(participant.draining_calls.load(Ordering::SeqCst), 2);
            assert!(!participant.draining.load(Ordering::SeqCst));
            assert_eq!(participant.forced.load(Ordering::SeqCst), 1);
        }
    }
}
