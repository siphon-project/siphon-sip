//! Draining the registrar's and the registrant's state-change broadcasts into
//! their consumers, and recovering when a consumer falls behind.
//!
//! Both publish on a bounded `tokio::sync::broadcast` channel. A receiver that
//! falls more than the channel's capacity behind gets `RecvError::Lagged(n)`:
//! `n` events are gone, and it resumes from the oldest one still held. Treating
//! that as the end of the stream (`while let Ok(..) = recv().await`) stops every
//! consumer for the life of the process with nothing logged, which is what a
//! registration storm after a restart, against a slow `@registrar.on_change`
//! handler, does.
//!
//! So a lag is counted (`siphon_event_consumer_lagged_total`), logged, and
//! answered with a **snapshot**: one delivery per AoR the source holds, tagged
//! `snapshot` rather than a change, each reading the AoR's current state the way
//! every live event already does. A consumer that keeps its own copy is whole
//! again for every AoR still held. An AoR whose bindings went away inside the
//! lost window is not in the snapshot; the events still held after the lag are
//! delivered once the snapshot is done and may name it, but if its removal was
//! among the `n` lost, only a consumer that reconciles against the full set
//! learns it is gone.
//!
//! Only the end of the channel (`RecvError::Closed`, the source dropped) ends
//! a loop.

use std::future::Future;
use std::sync::Arc;

use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::metrics::event_lag::{record_lag, LaggedConsumer};
use crate::registrant::{RegistrantEvent, RegistrantManager};
use crate::registrar::{Registrar, RegistrationEvent};

/// The `event` a delivery carries when it re-reports held state after a lag
/// instead of reporting a change.
pub(crate) const SNAPSHOT: &str = "snapshot";

/// One registrar delivery: which AoR, and what happened to it (`registered`,
/// `refreshed`, `deregistered`, `expired`, or [`SNAPSHOT`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistrarChange {
    pub aor: String,
    pub event: &'static str,
}

impl RegistrarChange {
    fn from_event(event: RegistrationEvent) -> Self {
        let (aor, event) = match event {
            RegistrationEvent::Registered { aor } => (aor, "registered"),
            RegistrationEvent::Refreshed { aor } => (aor, "refreshed"),
            RegistrationEvent::Deregistered { aor } => (aor, "deregistered"),
            RegistrationEvent::Expired { aor } => (aor, "expired"),
        };
        Self { aor, event }
    }

    /// Whether this re-reports held state rather than a change.
    pub fn is_snapshot(&self) -> bool {
        self.event == SNAPSHOT
    }
}

/// One registrant (outbound REGISTER) delivery: which AoR, what happened
/// (`registered`, `refreshed`, `failed`, `deregistered`, or [`SNAPSHOT`]), and
/// the status a `failed` carried.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistrantChange {
    pub aor: String,
    pub event: &'static str,
    pub status_code: Option<u16>,
}

impl RegistrantChange {
    fn from_event(event: RegistrantEvent) -> Self {
        let (aor, event, status_code) = match event {
            RegistrantEvent::Registered { aor } => (aor, "registered", None),
            RegistrantEvent::Refreshed { aor } => (aor, "refreshed", None),
            RegistrantEvent::Failed { aor, status_code } => (aor, "failed", Some(status_code)),
            RegistrantEvent::Deregistered { aor } => (aor, "deregistered", None),
        };
        Self {
            aor,
            event,
            status_code,
        }
    }
}

/// What one `recv()` on a state-change broadcast came back with.
enum Received<T> {
    Event(T),
    Lagged(u64),
    Closed,
}

async fn receive<T: Clone>(receiver: &mut broadcast::Receiver<T>) -> Received<T> {
    match receiver.recv().await {
        Ok(event) => Received::Event(event),
        Err(broadcast::error::RecvError::Lagged(skipped)) => Received::Lagged(skipped),
        Err(broadcast::error::RecvError::Closed) => Received::Closed,
    }
}

/// Feed every registrar event to `deliver`, one at a time, until the channel
/// closes. A lag is counted and answered with one [`SNAPSHOT`] delivery per
/// registered AoR before the loop carries on with the events still held.
pub(crate) async fn drain_registrar_events<D, F>(
    mut receiver: broadcast::Receiver<RegistrationEvent>,
    registrar: Arc<Registrar>,
    mut deliver: D,
) where
    D: FnMut(RegistrarChange) -> F,
    F: Future<Output = ()>,
{
    loop {
        match receive(&mut receiver).await {
            Received::Event(event) => deliver(RegistrarChange::from_event(event)).await,
            Received::Lagged(skipped) => {
                record_lag(LaggedConsumer::Registrar, skipped);
                let aors = registrar.registered_aors();
                warn!(
                    skipped,
                    republished = aors.len(),
                    "registrar events: @registrar.on_change and RegistrationChanged fell behind \
                     the registrar and lost events; re-publishing the current state of every \
                     registered AoR as a snapshot. A removal among the lost events reaches only \
                     a consumer that reconciles against the full set. Counted in \
                     siphon_event_consumer_lagged_total{{consumer=\"registrar\"}}"
                );
                for aor in aors {
                    deliver(RegistrarChange {
                        aor,
                        event: SNAPSHOT,
                    })
                    .await;
                }
            }
            Received::Closed => {
                info!(
                    "registrar events: the registrar's event channel closed, the event task ends"
                );
                break;
            }
        }
    }
}

/// Feed every registrant event to `deliver`, one at a time, until the channel
/// closes. A lag is counted and answered with one [`SNAPSHOT`] delivery per
/// outbound registration before the loop carries on.
pub(crate) async fn drain_registrant_events<D, F>(
    mut receiver: broadcast::Receiver<RegistrantEvent>,
    registrant: Arc<RegistrantManager>,
    mut deliver: D,
) where
    D: FnMut(RegistrantChange) -> F,
    F: Future<Output = ()>,
{
    loop {
        match receive(&mut receiver).await {
            Received::Event(event) => deliver(RegistrantChange::from_event(event)).await,
            Received::Lagged(skipped) => {
                record_lag(LaggedConsumer::Registrant, skipped);
                let aors: Vec<String> = registrant
                    .list()
                    .into_iter()
                    .map(|(aor, _, _)| aor)
                    .collect();
                warn!(
                    skipped,
                    republished = aors.len(),
                    "registrant events: @registration.on_change fell behind the outbound \
                     registrations and lost events; re-publishing the current state of every \
                     outbound registration as a snapshot. Counted in \
                     siphon_event_consumer_lagged_total{{consumer=\"registrant\"}}"
                );
                for aor in aors {
                    deliver(RegistrantChange {
                        aor,
                        event: SNAPSHOT,
                        status_code: None,
                    })
                    .await;
                }
            }
            Received::Closed => {
                info!(
                    "registrant events: the registrant's event channel closed, the event task ends"
                );
                break;
            }
        }
    }
}

#[cfg(test)]
#[path = "registration_events_tests.rs"]
mod tests;
