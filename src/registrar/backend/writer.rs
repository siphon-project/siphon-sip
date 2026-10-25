//! The registrar's write-through path: the latest desired backend state per
//! key, held in a [`coalesce`](super::coalesce) queue and drained in
//! concurrent batches by one writer task.
//!
//! Split out of `backend.rs` (which is at its size budget) as the piece with a
//! lifetime of its own: everything here is about getting the SIP path's writes
//! to the backend, not about how a binding is stored.
//!
//! Every write the registrar issues is *state*, not an event: the whole binding
//! set of an AoR (or its removal), or the whole auxiliary state of an AoR (or
//! its removal). Each backend applies one as a full replacement of its key, and
//! the indexes a backend keeps beside it (the Redis AoR index, the TTL of the
//! state key) move in the same operation. The alias index, the implicit set and
//! the flow-token index are not written at all: a restore derives them from the
//! binding rows and the `associated_uris` of the state row. So only the latest
//! write to a key matters, and a newer one replaces an older one still waiting.
//!
//! "Latest" is the snapshot's order, not the order writes reach the queue: the
//! registrar takes a [`WriteSequence`] while it holds the AoR's entry, so a save
//! descheduled between its snapshot and its enqueue cannot land after a newer
//! one.
//!
//! [`BackendWriter`]'s methods never wait, so they are safe from a thread
//! attached to the interpreter and from a tokio worker.

use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};

use super::coalesce::{self, DrainEvent, Drainer, QueueHandle, QueueKind, QueuedWrite, WriteSink};
use super::{BackendError, RegistrarBackend, StoredAorState, StoredContact, WriteSequence};

#[cfg(test)]
use super::coalesce::EnqueueHook;

/// How many `count_aors` reads may wait for the writer at once before a new
/// one fails instead of queueing. Reads are rare (a script asking for the
/// distributed count); the bound only keeps a stuck backend from collecting
/// callers.
const READ_QUEUE_CAPACITY: usize = 64;

/// How long [`BackendWriter::count_aors`] waits for its answer.
///
/// The writer applies every pending write before it answers, so the count
/// includes them, and its wait is that drain plus one round trip. During an
/// outage that is unbounded without a deadline. A caller that gets `Timeout`
/// still has the in-memory count to fall back on, which is the answer it had
/// before the backend existed.
const COUNT_AORS_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the writer task asks the backend to drop what has expired
/// ([`RegistrarBackend::purge_expired`]).
///
/// Often enough that an index or table never holds more than a minute of
/// expired AoRs beyond what any reader already filters out, rare enough to
/// cost nothing next to the write-through traffic.
const PURGE_INTERVAL: Duration = Duration::from_secs(60);

/// Which of an AoR's two backend keys a write replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Keyspace {
    /// The binding set (Redis hash + index member, Postgres contact rows).
    Bindings,
    /// The auxiliary state (Service-Route, P-Asserted-Identity,
    /// P-Associated-URI).
    State,
}

/// One backend key: an AoR's binding set or its auxiliary state.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WriteKey {
    keyspace: Keyspace,
    aor: String,
}

impl std::fmt::Display for WriteKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.keyspace {
            Keyspace::Bindings => formatter.write_str(&self.aor),
            Keyspace::State => write!(formatter, "state:{}", self.aor),
        }
    }
}

/// One write-through: the desired backend state of one of an AoR's keys,
/// applied as a full replacement of that key.
#[derive(Debug)]
pub enum BackendWrite {
    /// Replace the AoR's binding set ([`RegistrarBackend::save`]).
    Save(Vec<StoredContact>),
    /// Remove the AoR's binding set ([`RegistrarBackend::remove`]).
    Remove,
    /// Replace the AoR's auxiliary state ([`RegistrarBackend::save_aor_state`]).
    SaveState(StoredAorState),
    /// Remove the AoR's auxiliary state ([`RegistrarBackend::remove_aor_state`]).
    RemoveState,
}

impl BackendWrite {
    fn keyspace(&self) -> Keyspace {
        match self {
            Self::Save(_) | Self::Remove => Keyspace::Bindings,
            Self::SaveState(_) | Self::RemoveState => Keyspace::State,
        }
    }

    /// Apply this write to `backend` for `aor` with the matching trait method.
    pub async fn apply<B: RegistrarBackend + ?Sized>(
        &self,
        backend: &B,
        aor: &str,
    ) -> Result<(), BackendError> {
        match self {
            Self::Save(contacts) => backend.save(aor, contacts).await,
            Self::Remove => backend.remove(aor).await,
            Self::SaveState(state) => backend.save_aor_state(aor, state).await,
            Self::RemoveState => backend.remove_aor_state(aor).await,
        }
    }
}

impl QueuedWrite for BackendWrite {
    fn label(&self) -> &'static str {
        match self {
            Self::Save(_) => "save",
            Self::Remove => "remove",
            Self::SaveState(_) => "save_aor_state",
            Self::RemoveState => "remove_aor_state",
        }
    }
}

impl<B: RegistrarBackend> WriteSink<WriteKey, BackendWrite> for B {
    async fn apply_batch(
        &self,
        writes: &[(&WriteKey, &BackendWrite)],
    ) -> Vec<Result<(), BackendError>> {
        let writes: Vec<(&str, &BackendWrite)> = writes
            .iter()
            .map(|(key, write)| (key.aor.as_str(), *write))
            .collect();
        RegistrarBackend::apply_batch(self, &writes).await
    }
}

/// A `count_aors` read waiting for the writer task.
#[derive(Debug)]
struct CountRequest {
    reply: oneshot::Sender<Result<usize, BackendError>>,
    /// When the caller asked, so the writer can report how long it waited for
    /// the writes ahead of it, the part of a slow `count_aors` that is draining
    /// rather than the backend.
    queued_at: Instant,
}

/// Handle for the registrar's write-through to its backend.
///
/// Writes are fire-and-forget and never wait; the writer task applies them and
/// retries what the backend refuses. Reads (`count_aors`) round-trip to the
/// writer task and propagate backend errors to the caller.
#[derive(Debug, Clone)]
pub struct BackendWriter {
    queue: QueueHandle<WriteKey, BackendWrite>,
    reads: mpsc::Sender<CountRequest>,
    /// Records every write instead of applying it ([`recording_writer`]).
    #[cfg(test)]
    record: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
}

impl BackendWriter {
    fn new(queue: QueueHandle<WriteKey, BackendWrite>, reads: mpsc::Sender<CountRequest>) -> Self {
        Self {
            queue,
            reads,
            #[cfg(test)]
            record: None,
        }
    }

    /// The order of a snapshot about to be written. Take it while holding the
    /// lock that orders the state being snapshotted (the AoR's entry), and
    /// pass it to the `*_at` method that writes the snapshot.
    pub fn sequence(&self) -> WriteSequence {
        self.queue.sequence()
    }

    fn enqueue(&self, aor: &str, write: BackendWrite, sequence: WriteSequence) {
        #[cfg(test)]
        if let Some(record) = &self.record {
            record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(describe(aor, &write));
            return;
        }
        let key = WriteKey {
            keyspace: write.keyspace(),
            aor: aor.to_string(),
        };
        self.queue.enqueue(key, aor, write, sequence);
    }

    /// Keys whose latest write has not been applied yet, waiting or in flight.
    #[cfg(test)]
    pub(crate) fn pending_writes(&self) -> usize {
        self.queue.pending_writes()
    }

    /// How long the oldest pending write has waited, as the gauge reports it.
    #[cfg(test)]
    pub(crate) fn oldest_pending(&self) -> Duration {
        self.queue.oldest_pending()
    }

    /// Replace the AoR's backend binding set with `contacts`, ordered as of
    /// now. A caller racing other writers to the AoR uses [`save_at`].
    ///
    /// [`save_at`]: Self::save_at
    pub fn save(&self, aor: &str, contacts: Vec<StoredContact>) {
        self.save_at(aor, contacts, self.sequence());
    }

    /// Replace the AoR's backend binding set with `contacts`, a snapshot taken
    /// at `sequence`. An older snapshot never replaces a newer one.
    pub fn save_at(&self, aor: &str, contacts: Vec<StoredContact>, sequence: WriteSequence) {
        self.enqueue(aor, BackendWrite::Save(contacts), sequence);
    }

    /// Remove the AoR's backend binding set, ordered as of now.
    pub fn remove(&self, aor: &str) {
        self.remove_at(aor, self.sequence());
    }

    /// Remove the AoR's backend binding set, a removal decided at `sequence`.
    pub fn remove_at(&self, aor: &str, sequence: WriteSequence) {
        self.enqueue(aor, BackendWrite::Remove, sequence);
    }

    /// Replace the AoR's auxiliary state (Service-Route, P-Asserted-Identity,
    /// P-Associated-URI), ordered as of now. An empty state removes the entry.
    pub fn save_aor_state(&self, aor: &str, state: StoredAorState) {
        self.save_aor_state_at(aor, state, self.sequence());
    }

    /// Replace the AoR's auxiliary state with a snapshot taken at `sequence`.
    pub fn save_aor_state_at(&self, aor: &str, state: StoredAorState, sequence: WriteSequence) {
        self.enqueue(aor, BackendWrite::SaveState(state), sequence);
    }

    /// Remove the AoR's auxiliary state, ordered as of now.
    pub fn remove_aor_state(&self, aor: &str) {
        self.remove_aor_state_at(aor, self.sequence());
    }

    /// Remove the AoR's auxiliary state, a removal decided at `sequence`.
    pub fn remove_aor_state_at(&self, aor: &str, sequence: WriteSequence) {
        self.enqueue(aor, BackendWrite::RemoveState, sequence);
    }

    /// Ask the backend for the current number of registered AoRs.
    ///
    /// Authoritative across all siphon instances sharing the backend (Redis,
    /// Postgres), and inclusive of every write issued before it: the writer
    /// applies what is pending before it asks. Bounded by
    /// [`COUNT_AORS_TIMEOUT`].
    ///
    /// Returns [`BackendError::Connection`] if the writer task has shut down or
    /// too many reads are already waiting, and [`BackendError::Timeout`] if the
    /// answer did not arrive in time. On a timeout the read still runs; only
    /// its reply is discarded.
    pub async fn count_aors(&self) -> Result<usize, BackendError> {
        let (reply, answer) = oneshot::channel();
        let started = Instant::now();

        // try_send rather than send().await: awaiting room behind a stuck
        // backend is the unbounded wait the deadline below exists to remove.
        self.reads
            .try_send(CountRequest {
                reply,
                queued_at: started,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => BackendError::Connection(
                    "too many registrar backend reads are already waiting".to_string(),
                ),
                mpsc::error::TrySendError::Closed(_) => {
                    BackendError::Connection("registrar backend writer task is closed".to_string())
                }
            })?;

        let result = match tokio::time::timeout(COUNT_AORS_TIMEOUT, answer).await {
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

/// Spawn the task that applies write-throughs to `backend`.
///
/// Returns a [`BackendWriter`] handle that can be cloned into the Registrar.
/// The task runs until every handle is dropped.
pub fn spawn_backend_writer<B: RegistrarBackend + 'static>(backend: B) -> BackendWriter {
    let (queue, drainer) = coalesce::queue(QueueKind::Registrar);
    let (reads, read_queue) = mpsc::channel(READ_QUEUE_CAPACITY);
    tokio::spawn(
        WriterTask {
            backend,
            drainer,
            reads: read_queue,
        }
        .run(),
    );
    BackendWriter::new(queue, reads)
}

/// [`spawn_backend_writer`] with `hook` run at the start of every enqueue.
#[cfg(test)]
pub(crate) fn spawn_backend_writer_with_hook<B: RegistrarBackend + 'static>(
    backend: B,
    hook: EnqueueHook,
) -> BackendWriter {
    let writer = spawn_backend_writer(backend);
    writer.queue.set_hook(hook);
    writer
}

/// One write as a line, the operation, the AoR, and for a save the stored
/// contact URIs in stored order.
#[cfg(test)]
fn describe(aor: &str, write: &BackendWrite) -> String {
    match write {
        BackendWrite::Save(contacts) => {
            let uris: Vec<&str> = contacts
                .iter()
                .map(|contact| contact.uri.as_str())
                .collect();
            format!("save {aor} {uris:?}")
        }
        BackendWrite::Remove => format!("remove {aor}"),
        BackendWrite::SaveState(_) => format!("save_state {aor}"),
        BackendWrite::RemoveState => format!("remove_state {aor}"),
    }
}

/// A writer whose writes are recorded instead of applied, so a test can see
/// exactly which write-throughs a registrar operation issued, and in what order.
#[cfg(test)]
pub(crate) fn recording_writer() -> (BackendWriter, RecordedWrites) {
    let (queue, drainer) = coalesce::queue(QueueKind::Registrar);
    let (reads, read_queue) = mpsc::channel(READ_QUEUE_CAPACITY);
    let record = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut writer = BackendWriter::new(queue, reads);
    writer.record = Some(std::sync::Arc::clone(&record));
    (
        writer,
        RecordedWrites {
            record,
            _reads: read_queue,
            _drainer: drainer,
        },
    )
}

/// The receiving end of [`recording_writer`]. Holding it keeps the read queue
/// open (nothing answers it); dropping it closes the writer.
#[cfg(test)]
pub(crate) struct RecordedWrites {
    record: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    _reads: mpsc::Receiver<CountRequest>,
    _drainer: Drainer<WriteKey, BackendWrite>,
}

#[cfg(test)]
impl RecordedWrites {
    /// Every write issued since the last drain, one line each (see
    /// [`describe`]).
    pub(crate) fn drain(&mut self) -> Vec<String> {
        std::mem::take(
            &mut *self
                .record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

/// The writer task's state.
struct WriterTask<B> {
    backend: B,
    drainer: Drainer<WriteKey, BackendWrite>,
    reads: mpsc::Receiver<CountRequest>,
}

/// What woke the writer task.
enum Wake {
    Read(Option<CountRequest>),
    Purge,
    Drain(DrainEvent),
}

impl<B: RegistrarBackend> WriterTask<B> {
    async fn run(mut self) {
        let mut purge =
            tokio::time::interval_at(tokio::time::Instant::now() + PURGE_INTERVAL, PURGE_INTERVAL);
        purge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            self.drainer.attempt(&self.backend).await;
            // Reads and the purge first, so a steady stream of writes cannot
            // starve them; a read drains the pending writes itself.
            let wake = tokio::select! {
                biased;
                read = self.reads.recv() => Wake::Read(read),
                _ = purge.tick() => Wake::Purge,
                event = self.drainer.next_event() => Wake::Drain(event),
            };
            match wake {
                Wake::Read(Some(request)) => {
                    self.drainer.attempt(&self.backend).await;
                    self.answer(request).await;
                }
                // Every handle is gone: nothing more can be written.
                Wake::Read(None) | Wake::Drain(DrainEvent::Closed) => break,
                // On the same task as the writes, so a purge never races one.
                Wake::Purge => self.purge().await,
                Wake::Drain(DrainEvent::Write | DrainEvent::Retry) => {}
            }
        }
        self.drainer.finish(&self.backend).await;
    }

    async fn answer(&self, request: CountRequest) {
        // Recorded before the backend call so the two histograms separate
        // "the writes ahead of it took long" from "the backend was slow".
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .registrar_count_aors_queue_wait_seconds
                .observe(request.queued_at.elapsed().as_secs_f64());
        }
        let result = self.backend.count_aors().await;
        let _ = request.reply.send(result);
    }

    async fn purge(&self) {
        match self.backend.purge_expired().await {
            Ok(purged) if purged > 0 => {
                tracing::debug!(purged, "registrar backend dropped expired entries");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "registrar backend purge of expired entries failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer with no task behind it: writes stay pending (the drainer is
    /// held, never run), reads stay queued in a queue of `read_capacity`.
    fn idle_writer(
        read_capacity: usize,
    ) -> (
        BackendWriter,
        Drainer<WriteKey, BackendWrite>,
        mpsc::Receiver<CountRequest>,
    ) {
        let (queue, drainer) = coalesce::queue(QueueKind::Registrar);
        let (reads, read_queue) = mpsc::channel(read_capacity);
        (BackendWriter::new(queue, reads), drainer, read_queue)
    }

    fn pending_bindings(writer: &BackendWriter, aor: &str) -> Option<String> {
        let key = WriteKey {
            keyspace: Keyspace::Bindings,
            aor: aor.to_string(),
        };
        writer
            .queue
            .inspect(&key, |write| write.map(|write| describe(aor, write)))
    }

    /// The point of the pending map. A backend that is not draining makes
    /// writes wait, not vanish, and what waits is one entry per key however
    /// many writes that key has had: memory follows the AoRs, not the rate.
    #[tokio::test]
    async fn writes_nobody_drains_coalesce_per_key_rather_than_drop() {
        let (writer, _drainer, _reads) = idle_writer(1);

        for _ in 0..10_000 {
            writer.save("sip:a@example.com", Vec::new());
        }
        writer.save("sip:b@example.com", Vec::new());
        writer.remove("sip:b@example.com");
        writer.save_aor_state("sip:a@example.com", StoredAorState::default());
        writer.remove_aor_state("sip:c@example.com");

        assert_eq!(writer.pending_writes(), 4);
        assert_eq!(
            pending_bindings(&writer, "sip:b@example.com").as_deref(),
            Some("remove sip:b@example.com")
        );
    }

    /// The snapshot's order decides, not the order writes reach the queue: a
    /// snapshot taken earlier and enqueued later never replaces a newer one.
    #[tokio::test]
    async fn an_older_snapshot_enqueued_later_does_not_replace_a_newer_one() {
        let (writer, _drainer, _reads) = idle_writer(1);
        let older = writer.sequence();
        let newer = writer.sequence();

        writer.remove_at("sip:a@example.com", newer);
        writer.save_at("sip:a@example.com", Vec::new(), older);

        assert_eq!(
            pending_bindings(&writer, "sip:a@example.com").as_deref(),
            Some("remove sip:a@example.com")
        );
    }

    /// A read behind a full read queue fails immediately with a reason.
    /// Awaiting room would reintroduce the unbounded wait the deadline removes.
    #[tokio::test]
    async fn count_aors_on_a_full_read_queue_fails_instead_of_waiting() {
        let (writer, _drainer, _reads) = idle_writer(1);
        let (reply, _answer) = oneshot::channel();
        writer
            .reads
            .try_send(CountRequest {
                reply,
                queued_at: Instant::now(),
            })
            .expect("room for one");

        let started = Instant::now();
        let result = writer.count_aors().await;

        assert!(matches!(result, Err(BackendError::Connection(_))));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "it must fail fast, not wait for room"
        );
    }

    /// A writer whose task is gone answers rather than hanging.
    #[tokio::test]
    async fn count_aors_reports_a_closed_writer() {
        let (writer, recorded) = recording_writer();
        drop(recorded);

        assert!(matches!(
            writer.count_aors().await,
            Err(BackendError::Connection(_))
        ));
    }

    /// A read nobody answers leaves `count_aors` waiting, and the deadline is
    /// what ends it. Without one the caller waits for as long as the backend
    /// stays down.
    #[tokio::test(start_paused = true)]
    async fn count_aors_gives_up_at_the_deadline() {
        // Held so the queue stays open — a dropped receiver would end the
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

    /// A count includes every write issued before it, applied first.
    #[tokio::test]
    async fn count_aors_counts_the_writes_issued_before_it() {
        let stored = super::super::tests::sample_stored_contact();
        let writer = spawn_backend_writer(crate::registrar::backend::MemoryBackend::new());

        writer.save("sip:alice@example.com", vec![stored.clone()]);
        writer.save("sip:bob@example.com", vec![stored]);
        writer.remove("sip:bob@example.com");

        assert_eq!(writer.count_aors().await.expect("count"), 1);
    }

    /// Writes to a writer whose task has ended are refused, not parked in a
    /// map nothing will ever drain.
    #[tokio::test]
    async fn a_writer_whose_task_ended_holds_nothing() {
        let (writer, drainer, _reads) = idle_writer(1);
        writer.save("sip:before@example.com", Vec::new());
        drop(drainer);

        writer.save("sip:after@example.com", Vec::new());

        assert_eq!(writer.pending_writes(), 0);
    }

    /// A backend whose count differs from the length of its list (empty), and
    /// which counts the purges the writer runs.
    #[derive(Debug, Default)]
    struct Probe {
        purged: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl RegistrarBackend for Probe {
        async fn save(&self, _: &str, _: &[StoredContact]) -> Result<(), BackendError> {
            Ok(())
        }
        async fn load(&self, _: &str) -> Result<Vec<StoredContact>, BackendError> {
            Ok(Vec::new())
        }
        async fn remove(&self, _: &str) -> Result<(), BackendError> {
            Ok(())
        }
        async fn exists(&self, _: &str) -> Result<bool, BackendError> {
            Ok(false)
        }
        async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
            Ok(Vec::new())
        }
        async fn save_aor_state(&self, _: &str, _: &StoredAorState) -> Result<(), BackendError> {
            Ok(())
        }
        async fn load_aor_state(&self, _: &str) -> Result<Option<StoredAorState>, BackendError> {
            Ok(None)
        }
        async fn remove_aor_state(&self, _: &str) -> Result<(), BackendError> {
            Ok(())
        }
        async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
            Ok(Vec::new())
        }
        async fn count_aors(&self) -> Result<usize, BackendError> {
            Ok(42)
        }
        async fn purge_expired(&self) -> Result<usize, BackendError> {
            self.purged
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(0)
        }
    }

    /// The count comes from the backend's own `count_aors`, not from listing
    /// every AoR: listing is the keyspace walk an index exists to avoid.
    #[tokio::test]
    async fn count_aors_asks_the_backend_for_its_count_not_its_list() {
        let writer = spawn_backend_writer(Probe::default());
        assert_eq!(writer.count_aors().await.expect("count"), 42);
    }

    /// The writer purges on its own, every interval, so expired entries go
    /// even when nothing ever asks for the count.
    #[tokio::test(start_paused = true)]
    async fn the_writer_purges_expired_entries_every_interval() {
        let purged = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let probe = Probe {
            purged: std::sync::Arc::clone(&purged),
        };
        let _writer = spawn_backend_writer(probe);

        tokio::time::sleep(PURGE_INTERVAL / 2).await;
        assert_eq!(purged.load(std::sync::atomic::Ordering::SeqCst), 0);
        tokio::time::sleep(PURGE_INTERVAL * 3).await;
        assert_eq!(purged.load(std::sync::atomic::Ordering::SeqCst), 3);
    }
}

#[cfg(test)]
#[path = "writer_tests.rs"]
mod write_through_tests;
