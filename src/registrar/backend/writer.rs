//! The registrar's write-through queue: a bounded channel in front of a task
//! that applies each command to the L2 backend.
//!
//! Split out of `backend.rs` (which is at its size budget) as the piece with a
//! lifetime of its own: everything here is about the queue between the SIP path
//! and the backend, not about how a binding is stored.
//!
//! The queue is **bounded**, and every bound here exists because the thing it
//! bounds was previously unbounded in a way an outage made unbounded in time as
//! well as in space. A Redis outage makes each operation burn its full response
//! timeout, so the drain rate collapses while a REGISTER storm keeps filling the
//! queue: memory grows without limit, and a read queued behind it waits behind
//! every write already there. The bound turns that into a loss that is counted
//! and alertable rather than one that is silent until the process dies.

use std::time::{Duration, Instant};

use super::{BackendError, RegistrarBackend, StoredAorState, StoredContact};

/// How many write-through commands may be queued before new ones are dropped.
///
/// Generous against a REGISTER storm on a healthy backend — the writer drains
/// far faster than SIP can fill it when Redis is answering — and finite so an
/// outage cannot turn the queue into an unbounded memory sink. A full queue
/// means the backend has been unable to keep up for long enough that dropping
/// the oldest work is no longer the bigger problem.
const WRITER_QUEUE_CAPACITY: usize = 16_384;

/// How long [`BackendWriter::count_aors`] waits for its answer.
///
/// It is a read behind a queue of writes, so its wait is the queue's depth
/// times each operation's cost, not one round trip. Without a deadline it
/// inherits the whole queue's latency, and during an outage that is unbounded.
/// A caller that gets `Timeout` still has the in-memory count to fall back on,
/// which is the answer it had before the backend existed.
const COUNT_AORS_TIMEOUT: Duration = Duration::from_secs(5);

/// Commands sent to the backend writer task.
pub(super) enum BackendCommand {
    Save {
        aor: String,
        contacts: Vec<StoredContact>,
    },
    Remove {
        aor: String,
    },
    SaveAorState {
        aor: String,
        state: StoredAorState,
    },
    RemoveAorState {
        aor: String,
    },
    CountAors {
        reply: tokio::sync::oneshot::Sender<Result<usize, BackendError>>,
        /// When the caller enqueued it, so the loop can report how long it sat
        /// behind the writes ahead of it — the part of a slow `count_aors` that
        /// is queueing rather than Redis.
        queued_at: Instant,
    },
}

impl BackendCommand {
    /// The label this command is counted under when it is dropped.
    fn label(&self) -> &'static str {
        match self {
            Self::Save { .. } => "save",
            Self::Remove { .. } => "remove",
            Self::SaveAorState { .. } => "save_aor_state",
            Self::RemoveAorState { .. } => "remove_aor_state",
            Self::CountAors { .. } => "count_aors",
        }
    }
}

/// Handle for sending commands to a backend task.
///
/// Writes (Save / Remove) are fire-and-forget; failures are logged by the
/// background task.  Reads (CountAors) round-trip through a oneshot reply
/// channel and propagate backend errors to the caller.
#[derive(Debug, Clone)]
pub struct BackendWriter {
    tx: tokio::sync::mpsc::Sender<BackendCommand>,
}

impl BackendWriter {
    /// Enqueue a command, or drop it and say so.
    ///
    /// Never waits for space. The callers are on the SIP path and are not
    /// async, so the only alternatives to dropping are blocking a transport
    /// thread or growing without limit, and both of those fail the whole node
    /// rather than one binding's persistence.
    ///
    /// A dropped write leaves L1 and L2 disagreeing: the binding is live in
    /// memory and absent from the backend, so a restart loses it. That is worth
    /// a `warn!` and a counter every time, never a silent discard.
    fn enqueue(&self, command: BackendCommand) {
        let label = command.label();
        match self.tx.try_send(command) {
            Ok(()) => {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .registrar_backend_queue_depth
                        .set(self.queue_depth() as i64);
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tracing::warn!(
                    command = label,
                    capacity = WRITER_QUEUE_CAPACITY,
                    "registrar backend write-through queue is full; dropping the command \
                     — the backend is not draining and this binding will not survive a restart"
                );
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .registrar_backend_dropped_total
                        .with_label_values(&[label, "queue_full"])
                        .inc();
                }
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tracing::warn!(
                    command = label,
                    "registrar backend writer task is gone; dropping the command"
                );
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .registrar_backend_dropped_total
                        .with_label_values(&[label, "closed"])
                        .inc();
                }
            }
        }
    }

    /// Commands currently queued.
    fn queue_depth(&self) -> usize {
        WRITER_QUEUE_CAPACITY.saturating_sub(self.tx.capacity())
    }

    /// Enqueue a save (full AoR replacement) to the backend.
    pub fn save(&self, aor: &str, contacts: Vec<StoredContact>) {
        self.enqueue(BackendCommand::Save {
            aor: aor.to_string(),
            contacts,
        });
    }

    /// Enqueue a remove (all contacts for an AoR) to the backend.
    pub fn remove(&self, aor: &str) {
        self.enqueue(BackendCommand::Remove {
            aor: aor.to_string(),
        });
    }

    /// Enqueue an auxiliary-state write (Service-Route, P-Asserted-Identity,
    /// P-Associated-URI) for an AoR.  An empty state removes the entry.
    pub fn save_aor_state(&self, aor: &str, state: StoredAorState) {
        self.enqueue(BackendCommand::SaveAorState {
            aor: aor.to_string(),
            state,
        });
    }

    /// Enqueue a removal of the auxiliary state for an AoR.
    pub fn remove_aor_state(&self, aor: &str) {
        self.enqueue(BackendCommand::RemoveAorState {
            aor: aor.to_string(),
        });
    }

    /// Ask the backend for the current number of registered AoRs.
    ///
    /// Authoritative across all siphon instances sharing the backend (Redis,
    /// Postgres).  Bounded by [`COUNT_AORS_TIMEOUT`]: this is a read queued
    /// behind however many writes are already in flight, so its wait is the
    /// queue's, not one operation's.
    ///
    /// Returns [`BackendError::Connection`] if the writer task has shut down or
    /// the queue is full, and [`BackendError::Timeout`] if the answer did not
    /// arrive in time. On a timeout the queued command still runs; only its
    /// reply is discarded.
    pub async fn count_aors(&self) -> Result<usize, BackendError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let started = Instant::now();

        // try_send rather than send().await for the reason the writes use it:
        // awaiting space on a full queue is the unbounded wait this is here to
        // remove, just moved one channel earlier.
        self.tx
            .try_send(BackendCommand::CountAors {
                reply: tx,
                queued_at: started,
            })
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => BackendError::Connection(
                    "registrar backend write-through queue is full".to_string(),
                ),
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    BackendError::Connection("registrar backend writer task is closed".to_string())
                }
            })?;

        let result = match tokio::time::timeout(COUNT_AORS_TIMEOUT, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(BackendError::Connection(
                "registrar backend reply channel dropped".to_string(),
            )),
            Err(_) => Err(BackendError::Timeout(format!(
                "registrar backend did not answer count_aors within {}s",
                COUNT_AORS_TIMEOUT.as_secs()
            ))),
        };

        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .registrar_count_aors_duration_seconds
                .observe(started.elapsed().as_secs_f64());
        }
        result
    }
}

/// Spawn a background task that processes write-through commands.
///
/// Returns a [`BackendWriter`] handle that can be cloned into the Registrar.
pub fn spawn_backend_writer<B: RegistrarBackend + 'static>(backend: B) -> BackendWriter {
    let (tx, rx) = tokio::sync::mpsc::channel(WRITER_QUEUE_CAPACITY);
    tokio::spawn(backend_writer_loop(backend, rx));
    BackendWriter { tx }
}

/// A writer whose commands are recorded instead of applied, so a test can see
/// exactly which write-throughs a registrar operation issued, and in what order.
#[cfg(test)]
pub(crate) fn recording_writer() -> (BackendWriter, RecordedWrites) {
    let (tx, rx) = tokio::sync::mpsc::channel(WRITER_QUEUE_CAPACITY);
    (BackendWriter { tx }, RecordedWrites(rx))
}

/// A writer whose queue holds `capacity` commands and is never drained, so a
/// test can fill it and observe what happens to the next one.
#[cfg(test)]
pub(crate) fn saturating_writer(capacity: usize) -> (BackendWriter, RecordedWrites) {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    (BackendWriter { tx }, RecordedWrites(rx))
}

/// The receiving end of [`recording_writer`].
#[cfg(test)]
pub(crate) struct RecordedWrites(tokio::sync::mpsc::Receiver<BackendCommand>);

#[cfg(test)]
impl RecordedWrites {
    /// Every command issued since the last drain, one line each: the operation,
    /// the AoR, and for a save the stored contact URIs in stored order.
    pub(crate) fn drain(&mut self) -> Vec<String> {
        let mut recorded = Vec::new();
        while let Ok(command) = self.0.try_recv() {
            recorded.push(match command {
                BackendCommand::Save { aor, contacts } => {
                    let uris: Vec<&str> = contacts
                        .iter()
                        .map(|contact| contact.uri.as_str())
                        .collect();
                    format!("save {aor} {uris:?}")
                }
                BackendCommand::Remove { aor } => format!("remove {aor}"),
                BackendCommand::SaveAorState { aor, .. } => format!("save_state {aor}"),
                BackendCommand::RemoveAorState { aor } => format!("remove_state {aor}"),
                BackendCommand::CountAors { .. } => "count_aors".to_string(),
            });
        }
        recorded
    }
}

async fn backend_writer_loop<B: RegistrarBackend>(
    backend: B,
    mut rx: tokio::sync::mpsc::Receiver<BackendCommand>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            BackendCommand::Save { aor, contacts } => {
                if let Err(error) = backend.save(&aor, &contacts).await {
                    tracing::warn!(aor, %error, "registrar backend write-through failed");
                }
            }
            BackendCommand::Remove { aor } => {
                if let Err(error) = backend.remove(&aor).await {
                    tracing::warn!(aor, %error, "registrar backend write-through failed");
                }
            }
            BackendCommand::SaveAorState { aor, state } => {
                if let Err(error) = backend.save_aor_state(&aor, &state).await {
                    tracing::warn!(aor, %error, "registrar backend aor-state write-through failed");
                }
            }
            BackendCommand::RemoveAorState { aor } => {
                if let Err(error) = backend.remove_aor_state(&aor).await {
                    tracing::warn!(aor, %error, "registrar backend aor-state remove failed");
                }
            }
            BackendCommand::CountAors { reply, queued_at } => {
                // Recorded before the backend call so the two histograms
                // separate "the queue was long" from "Redis was slow" — the
                // first is fixed by draining faster, the second is not.
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .registrar_count_aors_queue_wait_seconds
                        .observe(queued_at.elapsed().as_secs_f64());
                }
                let result = backend.all_aors().await.map(|aors| aors.len());
                let _ = reply.send(result);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound's whole point. A queue that has stopped draining must refuse
    /// new work rather than grow, and the refusal must be visible — a silent
    /// discard here is a binding that vanishes at the next restart with nothing
    /// in the log to say why.
    #[tokio::test]
    async fn a_full_queue_drops_the_next_write_rather_than_growing() {
        let (writer, mut recorded) = saturating_writer(2);

        writer.save("sip:a@example.com", Vec::new());
        writer.save("sip:b@example.com", Vec::new());
        // Nothing drains this queue, so the third has nowhere to go.
        writer.save("sip:c@example.com", Vec::new());

        let drained = recorded.drain();
        assert_eq!(
            drained.len(),
            2,
            "the queue holds its capacity and no more: {drained:?}"
        );
        assert!(drained[0].starts_with("save sip:a@example.com"));
        assert!(drained[1].starts_with("save sip:b@example.com"));
    }

    /// A read behind a full queue fails immediately with a reason. Awaiting
    /// space would reintroduce exactly the unbounded wait the bound removes.
    #[tokio::test]
    async fn count_aors_on_a_full_queue_fails_instead_of_waiting() {
        let (writer, _recorded) = saturating_writer(1);
        writer.save("sip:a@example.com", Vec::new());

        let started = Instant::now();
        let result = writer.count_aors().await;

        assert!(matches!(result, Err(BackendError::Connection(_))));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "it must fail fast, not wait for space"
        );
    }

    /// A writer whose task is gone answers rather than hanging: the oneshot
    /// sender drops with the receiver, which used to surface as a `Connection`
    /// error and still must.
    #[tokio::test]
    async fn count_aors_reports_a_closed_writer() {
        let (writer, recorded) = recording_writer();
        drop(recorded);

        assert!(matches!(
            writer.count_aors().await,
            Err(BackendError::Connection(_))
        ));
    }

    /// A command that reaches a queue nobody drains leaves `count_aors`
    /// waiting, and the deadline is what ends it. Without one the caller waits
    /// for as long as the backend stays down.
    #[tokio::test(start_paused = true)]
    async fn count_aors_gives_up_at_the_deadline() {
        // Held so the channel stays open — a dropped receiver would end the
        // wait via the closed path instead of the deadline under test.
        let (writer, _recorded) = recording_writer();

        let result = writer.count_aors().await;

        assert!(
            matches!(result, Err(BackendError::Timeout(_))),
            "expected a timeout, got {result:?}"
        );
    }

    /// The happy path still works, and the reply carries the backend's answer.
    /// A save with no contacts is a removal, so each AoR needs a real binding
    /// for the backend to hold it at all.
    #[tokio::test]
    async fn count_aors_returns_the_backend_count() {
        let backend = crate::registrar::backend::MemoryBackend::new();
        let stored = super::super::tests::sample_stored_contact();
        backend
            .save("sip:alice@example.com", std::slice::from_ref(&stored))
            .await
            .expect("save");
        backend
            .save("sip:bob@example.com", std::slice::from_ref(&stored))
            .await
            .expect("save");

        let writer = spawn_backend_writer(backend);

        assert_eq!(writer.count_aors().await.expect("count"), 2);
    }
}
