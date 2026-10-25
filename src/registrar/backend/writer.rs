//! The registrar's write-through path: a pending map of the latest desired
//! backend state per key, drained in concurrent batches by one writer task.
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
//! That is what bounds the path. A FIFO queue grows with the write *rate*, so a
//! burst (a restart evicting thousands of restored bindings) or an outage (every
//! operation burning its timeout) had to either grow without limit or drop, and
//! it dropped: deletes that never landed came back at the next restore. The
//! pending map grows with the number of distinct keys written since the last
//! drain, which the registrar itself bounds (two per AoR), so it never drops a
//! write and never needs a cap. A write the backend refuses stays pending and is
//! retried with backoff.
//!
//! [`BackendWriter`]'s methods never wait: they take one short lock to replace
//! a map entry, so they are safe from a thread attached to the interpreter and
//! from a tokio worker.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot, Notify};

use super::{BackendError, RegistrarBackend, StoredAorState, StoredContact};

/// How many `count_aors` reads may wait for the writer at once before a new
/// one fails instead of queueing. Reads are rare (a script asking for the
/// distributed count); the bound only keeps a stuck backend from collecting
/// callers.
const READ_QUEUE_CAPACITY: usize = 64;

/// How many writes the writer has in flight against the backend at once.
///
/// Both backends pipeline concurrent operations on one connection (the Redis
/// multiplexed connection, the tokio-postgres client), so a batch costs about
/// one round trip rather than one per write. During an outage a batch costs at
/// most one operation timeout, because the writer stops at the first batch in
/// which nothing succeeds.
const WRITE_CONCURRENCY: usize = 128;

/// First retry delay after the backend refuses writes.
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Longest retry delay: how stale the backend can get after it recovers.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// A drained backlog keeping more slots than this gives them back, so the
/// table a restart burst grew does not stay at its peak for the process's life.
const BACKLOG_RETAINED_CAPACITY: usize = 1024;

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

type WriteKey = (Keyspace, String);

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

    /// The label this write is counted under.
    fn label(&self) -> &'static str {
        match self {
            Self::Save(_) => "save",
            Self::Remove => "remove",
            Self::SaveState(_) => "save_aor_state",
            Self::RemoveState => "remove_aor_state",
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

#[derive(Debug)]
struct PendingWrite {
    op: BackendWrite,
    /// When this key's backend copy first fell behind: kept when a newer write
    /// replaces the op, so the age gauge reports staleness, not churn.
    since: Instant,
}

#[derive(Debug, Default)]
struct PendingWrites {
    writes: HashMap<WriteKey, PendingWrite>,
    /// The earliest `since` in `writes`, so the age gauge needs no scan.
    oldest: Option<Instant>,
}

/// What the SIP path and the writer task share.
#[derive(Debug, Default)]
struct Shared {
    pending: Mutex<PendingWrites>,
    /// Signalled on every write; a write landing while the writer is busy
    /// leaves a permit, so it is never missed.
    wake: Notify,
    /// Writes the writer task has taken out of `pending` and not yet applied.
    held: AtomicUsize,
    /// The writer task is gone: nothing will apply a new write.
    closed: AtomicBool,
}

impl Shared {
    /// The pending map. A panic while it was held cannot leave it torn (every
    /// critical section is one map operation), so poisoning is ignored rather
    /// than turned into a lost write.
    fn pending(&self) -> MutexGuard<'_, PendingWrites> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
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
    shared: Arc<Shared>,
    reads: mpsc::Sender<CountRequest>,
    /// Records every write instead of applying it ([`recording_writer`]).
    #[cfg(test)]
    record: Option<Arc<Mutex<Vec<String>>>>,
}

impl BackendWriter {
    fn new(shared: Arc<Shared>, reads: mpsc::Sender<CountRequest>) -> Self {
        Self {
            shared,
            reads,
            #[cfg(test)]
            record: None,
        }
    }

    /// Make `op` the desired backend state of its key for `aor`.
    ///
    /// Never waits and never drops for lack of room: a write to a key that is
    /// already pending replaces the older one, which is correct because each
    /// is the key's full state. Only a writer task that is gone loses a write,
    /// and that is counted and logged.
    fn enqueue(&self, aor: &str, op: BackendWrite) {
        #[cfg(test)]
        if let Some(record) = &self.record {
            record
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(describe(aor, &op));
            return;
        }
        let label = op.label();
        if self.shared.closed.load(Ordering::Acquire) {
            tracing::warn!(
                command = label,
                aor,
                "registrar backend writer task is gone; dropping the write — \
                 this binding will not survive a restart"
            );
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics
                    .registrar_backend_dropped_total
                    .with_label_values(&[label, "closed"])
                    .inc();
            }
            return;
        }
        let key = (op.keyspace(), aor.to_string());
        let now = Instant::now();
        let (depth, replaced) = {
            let mut pending = self.shared.pending();
            let replaced = match pending.writes.entry(key) {
                Entry::Occupied(mut entry) => {
                    entry.get_mut().op = op;
                    true
                }
                Entry::Vacant(entry) => {
                    entry.insert(PendingWrite { op, since: now });
                    false
                }
            };
            pending.oldest.get_or_insert(now);
            (pending.writes.len(), replaced)
        };
        self.shared.wake.notify_one();
        if let Some(metrics) = crate::metrics::try_metrics() {
            if replaced {
                metrics.registrar_backend_coalesced_total.inc();
            }
            let held = self.shared.held.load(Ordering::Relaxed);
            metrics
                .registrar_backend_queue_depth
                .set(depth.saturating_add(held) as i64);
        }
    }

    /// Keys whose latest write has not been applied yet, waiting or in flight.
    #[cfg(test)]
    pub(crate) fn pending_writes(&self) -> usize {
        self.shared.pending().writes.len() + self.shared.held.load(Ordering::SeqCst)
    }

    /// Replace the AoR's backend binding set with `contacts`.
    pub fn save(&self, aor: &str, contacts: Vec<StoredContact>) {
        self.enqueue(aor, BackendWrite::Save(contacts));
    }

    /// Remove the AoR's backend binding set.
    pub fn remove(&self, aor: &str) {
        self.enqueue(aor, BackendWrite::Remove);
    }

    /// Replace the AoR's auxiliary state (Service-Route, P-Asserted-Identity,
    /// P-Associated-URI). An empty state removes the entry.
    pub fn save_aor_state(&self, aor: &str, state: StoredAorState) {
        self.enqueue(aor, BackendWrite::SaveState(state));
    }

    /// Remove the AoR's auxiliary state.
    pub fn remove_aor_state(&self, aor: &str) {
        self.enqueue(aor, BackendWrite::RemoveState);
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
    let shared = Arc::new(Shared::default());
    let (reads, read_queue) = mpsc::channel(READ_QUEUE_CAPACITY);
    let task = WriterTask {
        backend,
        shared: Arc::clone(&shared),
        reads: read_queue,
        backlog: HashMap::new(),
        backoff: INITIAL_BACKOFF,
        retry_at: None,
    };
    tokio::spawn(task.run());
    BackendWriter::new(shared, reads)
}

/// One write as a line, the operation, the AoR, and for a save the stored
/// contact URIs in stored order.
#[cfg(test)]
fn describe(aor: &str, op: &BackendWrite) -> String {
    match op {
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
    let (reads, read_queue) = mpsc::channel(READ_QUEUE_CAPACITY);
    let record = Arc::new(Mutex::new(Vec::new()));
    let mut writer = BackendWriter::new(Arc::new(Shared::default()), reads);
    writer.record = Some(Arc::clone(&record));
    (
        writer,
        RecordedWrites {
            record,
            _reads: read_queue,
        },
    )
}

/// The receiving end of [`recording_writer`]. Holding it keeps the read queue
/// open (nothing answers it); dropping it closes the writer.
#[cfg(test)]
pub(crate) struct RecordedWrites {
    record: Arc<Mutex<Vec<String>>>,
    _reads: mpsc::Receiver<CountRequest>,
}

#[cfg(test)]
impl RecordedWrites {
    /// Every write issued since the last drain, one line each (see
    /// [`describe`]).
    pub(crate) fn drain(&mut self) -> Vec<String> {
        std::mem::take(&mut *self.record.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

/// The writer task's state.
struct WriterTask<B> {
    backend: B,
    shared: Arc<Shared>,
    reads: mpsc::Receiver<CountRequest>,
    /// Writes taken out of the shared map and not yet applied. Only this task
    /// touches it, so the SIP path's lock is held for a swap, never for a
    /// backend round trip.
    backlog: HashMap<WriteKey, PendingWrite>,
    /// The delay before the next retry, doubled per failed attempt.
    backoff: Duration,
    /// Set while backing off: when the next attempt is due.
    retry_at: Option<tokio::time::Instant>,
}

/// What woke the writer task.
enum Wake {
    Read(Option<CountRequest>),
    Purge,
    Retry,
    Write,
}

impl<B: RegistrarBackend> WriterTask<B> {
    async fn run(mut self) {
        let mut purge =
            tokio::time::interval_at(tokio::time::Instant::now() + PURGE_INTERVAL, PURGE_INTERVAL);
        purge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let shared = Arc::clone(&self.shared);
        loop {
            self.attempt().await;
            self.publish();
            // Reads and the purge first, so a steady stream of writes cannot
            // starve them; a read drains the pending writes itself.
            let retry_at = self.retry_at;
            let wake = tokio::select! {
                biased;
                read = self.reads.recv() => Wake::Read(read),
                _ = purge.tick() => Wake::Purge,
                _ = sleep_until(retry_at), if retry_at.is_some() => Wake::Retry,
                _ = shared.wake.notified(), if retry_at.is_none() => Wake::Write,
            };
            match wake {
                Wake::Read(Some(request)) => {
                    self.attempt().await;
                    self.answer(request).await;
                }
                // Every handle is gone: nothing more can be written.
                Wake::Read(None) => break,
                // On the same task as the writes, so a purge never races one.
                Wake::Purge => self.purge().await,
                Wake::Retry => self.retry_at = None,
                Wake::Write => {}
            }
        }
        self.retry_at = None;
        self.attempt().await;
    }

    /// Apply everything pending, unless a retry is not due yet. A failure
    /// keeps the writes and schedules the retry.
    async fn attempt(&mut self) {
        if self.retry_at.is_some() {
            return;
        }
        match self.flush().await {
            Ok(()) => self.backoff = INITIAL_BACKOFF,
            Err(error) => {
                tracing::warn!(
                    %error,
                    pending = self.backlog.len(),
                    retry_in_ms = self.backoff.as_millis() as u64,
                    "registrar backend write-through failed; keeping the writes and retrying"
                );
                self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            }
        }
    }

    /// Move the shared map's writes into the backlog, a newer write replacing
    /// the op of an older one for the same key.
    fn absorb(&mut self) {
        let taken = {
            let mut pending = self.shared.pending();
            pending.oldest = None;
            std::mem::take(&mut pending.writes)
        };
        if self.backlog.is_empty() {
            self.backlog = taken;
        } else {
            for (key, write) in taken {
                match self.backlog.entry(key) {
                    Entry::Occupied(mut entry) => entry.get_mut().op = write.op,
                    Entry::Vacant(entry) => {
                        entry.insert(write);
                    }
                }
            }
        }
        self.shared.held.store(self.backlog.len(), Ordering::SeqCst);
    }

    /// Apply the backlog in concurrent batches.
    ///
    /// A write the backend refuses goes back in the backlog for the next
    /// attempt, and the attempt reports the error. A batch in which nothing
    /// succeeded means the backend is down, so the attempt stops there rather
    /// than spend an operation timeout on every remaining batch; a batch in
    /// which some writes succeeded means the backend is up and those keys are
    /// the problem, so the rest of the backlog still goes.
    async fn flush(&mut self) -> Result<(), BackendError> {
        self.absorb();
        let mut refused = Vec::new();
        let mut last_error = None;
        while !self.backlog.is_empty() {
            let keys: Vec<WriteKey> = self
                .backlog
                .keys()
                .take(WRITE_CONCURRENCY)
                .cloned()
                .collect();
            let batch: Vec<(WriteKey, PendingWrite)> = keys
                .iter()
                .filter_map(|key| self.backlog.remove_entry(key))
                .collect();
            let writes: Vec<(&str, &BackendWrite)> = batch
                .iter()
                .map(|((_, aor), write)| (aor.as_str(), &write.op))
                .collect();
            let mut results = self.backend.apply_batch(&writes).await;
            drop(writes);
            // A backend that answered for fewer writes than it was given has
            // not applied the rest: they stay pending.
            results.resize_with(batch.len(), || {
                Err(BackendError::Query(
                    "the backend returned no result for this write".to_string(),
                ))
            });
            let mut succeeded = 0usize;
            for ((key, write), result) in batch.into_iter().zip(results) {
                match result {
                    Ok(()) => succeeded += 1,
                    // Retrying an encoding failure fails the same way forever.
                    Err(BackendError::Serialization(error)) => {
                        let label = write.op.label();
                        tracing::error!(
                            aor = key.1,
                            command = label,
                            %error,
                            "registrar backend cannot encode the write; dropping it"
                        );
                        if let Some(metrics) = crate::metrics::try_metrics() {
                            metrics
                                .registrar_backend_dropped_total
                                .with_label_values(&[label, "unencodable"])
                                .inc();
                        }
                    }
                    Err(error) => {
                        refused.push((key, write));
                        last_error = Some(error);
                    }
                }
            }
            self.shared
                .held
                .store(self.backlog.len() + refused.len(), Ordering::SeqCst);
            if succeeded == 0 && last_error.is_some() {
                break;
            }
        }
        // Not re-tried in this attempt (they would fail the same way at once);
        // nothing newer for these keys can be in the backlog, which has not
        // absorbed since they were taken out of it.
        self.backlog.extend(refused);
        if self.backlog.is_empty() && self.backlog.capacity() > BACKLOG_RETAINED_CAPACITY {
            self.backlog = HashMap::new();
        }
        self.shared.held.store(self.backlog.len(), Ordering::SeqCst);
        last_error.map_or(Ok(()), Err)
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

    /// The pending count and the age of the oldest pending write.
    fn publish(&self) {
        let Some(metrics) = crate::metrics::try_metrics() else {
            return;
        };
        let (waiting, shared_oldest) = {
            let pending = self.shared.pending();
            (pending.writes.len(), pending.oldest)
        };
        // A scan, but of a backlog that is empty unless the backend is
        // refusing writes, and then at most once per retry.
        let oldest = self
            .backlog
            .values()
            .map(|write| write.since)
            .chain(shared_oldest)
            .min();
        metrics
            .registrar_backend_queue_depth
            .set(waiting.saturating_add(self.backlog.len()) as i64);
        metrics
            .registrar_backend_oldest_pending_seconds
            .set(oldest.map_or(0, |since| since.elapsed().as_secs()) as i64);
    }
}

impl<B> Drop for WriterTask<B> {
    /// However the task ends (every handle dropped, a panic, the runtime
    /// shutting down), later writes are refused loudly rather than left in a
    /// map nobody drains, and what was still pending is counted as lost.
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::Release);
        let left = std::mem::take(&mut self.shared.pending().writes);
        let lost = left.len() + self.backlog.len();
        self.shared.held.store(0, Ordering::SeqCst);
        if lost == 0 {
            return;
        }
        tracing::error!(
            lost,
            "registrar backend writer stopped with write-throughs not applied; \
             these bindings will not match the backend after a restart"
        );
        if let Some(metrics) = crate::metrics::try_metrics() {
            for write in left.values().chain(self.backlog.values()) {
                metrics
                    .registrar_backend_dropped_total
                    .with_label_values(&[write.op.label(), "closed"])
                    .inc();
            }
            metrics.registrar_backend_queue_depth.set(0);
        }
        self.backlog.clear();
    }
}

/// Sleep until `deadline`, or forever without one (its `select!` branch is
/// disabled then, so this is never polled).
async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer with no task behind it: writes stay pending, reads stay
    /// queued in a queue of `read_capacity`.
    fn idle_writer(read_capacity: usize) -> (BackendWriter, mpsc::Receiver<CountRequest>) {
        let (reads, read_queue) = mpsc::channel(read_capacity);
        (
            BackendWriter::new(Arc::new(Shared::default()), reads),
            read_queue,
        )
    }

    /// The point of the pending map. A backend that is not draining makes
    /// writes wait, not vanish, and what waits is one entry per key however
    /// many writes that key has had: memory follows the AoRs, not the rate.
    #[tokio::test]
    async fn writes_nobody_drains_coalesce_per_key_rather_than_drop() {
        let (writer, _reads) = idle_writer(1);

        for _ in 0..10_000 {
            writer.save("sip:a@example.com", Vec::new());
        }
        writer.save("sip:b@example.com", Vec::new());
        writer.remove("sip:b@example.com");
        writer.save_aor_state("sip:a@example.com", StoredAorState::default());
        writer.remove_aor_state("sip:c@example.com");

        assert_eq!(writer.pending_writes(), 4);
        let pending = writer.shared.pending();
        assert!(matches!(
            pending
                .writes
                .get(&(Keyspace::Bindings, "sip:b@example.com".to_string()))
                .map(|write| &write.op),
            Some(BackendWrite::Remove)
        ));
    }

    /// A read behind a full read queue fails immediately with a reason.
    /// Awaiting room would reintroduce the unbounded wait the deadline removes.
    #[tokio::test]
    async fn count_aors_on_a_full_read_queue_fails_instead_of_waiting() {
        let (writer, _reads) = idle_writer(1);
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
        let shared = Arc::new(Shared::default());
        let (reads, read_queue) = mpsc::channel(1);
        let writer = BackendWriter::new(Arc::clone(&shared), reads);
        writer.save("sip:before@example.com", Vec::new());
        drop(WriterTask {
            backend: crate::registrar::backend::MemoryBackend::new(),
            shared,
            reads: read_queue,
            backlog: HashMap::new(),
            backoff: INITIAL_BACKOFF,
            retry_at: None,
        });

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
