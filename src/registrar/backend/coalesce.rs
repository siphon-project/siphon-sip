//! A write-behind queue that holds the latest desired state per key and never
//! drops for lack of room: what both the registrar's and the iFC store's
//! write-throughs go through.
//!
//! Every write a user of this queue issues is the full state of one key (a
//! replacement or a removal), so only the latest one per key matters. A newer
//! write replaces an older one still waiting, and the queue grows with the
//! number of distinct keys written since the last drain, which the store behind
//! it bounds, rather than with the write rate. A write the sink refuses stays
//! pending and is retried with backoff.
//!
//! "Latest" is decided by a [`WriteSequence`] the caller takes from the queue
//! *while it holds the lock that orders its own state*, before it lets go and
//! enqueues. Two writers to one key can then reach the queue in either order
//! and the one whose snapshot is newer still wins: an older one arriving late
//! is discarded, both while the newer one waits and for a while after it was
//! applied ([`APPLIED_RETENTION`]).
//!
//! The handle never waits: an enqueue takes one short lock to replace a map
//! entry, so it is safe from a thread attached to the interpreter and from a
//! tokio worker. One task drains the queue with a [`Drainer`].

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Notify};

use super::BackendError;

/// How many writes the drainer has in flight against the sink at once.
///
/// The sinks pipeline concurrent operations on one connection (the Redis
/// multiplexed connection, the tokio-postgres client), so a batch costs about
/// one round trip rather than one per write. During an outage a batch costs at
/// most one operation timeout, because an attempt stops at the first batch in
/// which nothing succeeds.
pub(crate) const WRITE_CONCURRENCY: usize = 128;

/// First retry delay after the sink refuses writes.
const INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Longest retry delay: how stale the sink can get after it recovers.
const MAX_BACKOFF: Duration = Duration::from_secs(5);

/// A drained backlog keeping more slots than this gives them back, so the
/// table a burst grew does not stay at its peak for the process's life.
const BACKLOG_RETAINED_CAPACITY: usize = 1024;

/// How long the sequence of an applied write is remembered, so an older write
/// to the same key that reaches the queue afterwards is recognised as stale.
///
/// A caller takes its sequence under its own lock and enqueues right after,
/// with only in-memory work in between and no await, so the window a late
/// write needs is microseconds. Five seconds covers a thread descheduled in
/// that window many times over, and bounds the memory to the keys applied in
/// the last five seconds.
const APPLIED_RETENTION: Duration = Duration::from_secs(5);

/// The order of one write among all writes to a queue.
///
/// Take it with [`QueueHandle::sequence`] while holding the lock that orders
/// the state being snapshotted, so a higher sequence always means a newer
/// snapshot of that key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct WriteSequence(u64);

impl WriteSequence {
    /// A sequence older than every one a queue hands out.
    pub const OLDEST: Self = Self(0);
}

/// A write held by the queue: something with a label to count it under.
pub(crate) trait QueuedWrite: Send + Sync + 'static {
    /// The label this write is counted and logged under.
    fn label(&self) -> &'static str;
}

/// Where a [`Drainer`] applies writes.
pub(crate) trait WriteSink<K, W>: Send + Sync {
    /// Apply writes for distinct keys and return one result per write, in
    /// order. An error means the write was not applied (or may not have been)
    /// and is retried; a `Serialization` error is permanent and is dropped.
    fn apply_batch(
        &self,
        writes: &[(&K, &W)],
    ) -> impl std::future::Future<Output = Vec<Result<(), BackendError>>> + Send;
}

/// Which store a queue serves: names it in logs and picks its metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueueKind {
    Registrar,
    /// Only the Redis iFC writer drains one.
    #[cfg_attr(not(feature = "redis-backend"), allow(dead_code))]
    Ifc,
}

/// The metrics a queue reports to; only the registrar's has any.
struct QueueMetrics {
    depth: &'static prometheus::IntGauge,
    oldest: &'static prometheus::IntGauge,
    coalesced: &'static prometheus::IntCounter,
    dropped: &'static prometheus::IntCounterVec,
}

impl QueueKind {
    fn name(self) -> &'static str {
        match self {
            Self::Registrar => "registrar",
            Self::Ifc => "ifc",
        }
    }

    fn metrics(self) -> Option<QueueMetrics> {
        match self {
            Self::Registrar => crate::metrics::try_metrics().map(|metrics| QueueMetrics {
                depth: &metrics.registrar_backend_queue_depth,
                oldest: &metrics.registrar_backend_oldest_pending_seconds,
                coalesced: &metrics.registrar_backend_coalesced_total,
                dropped: &metrics.registrar_backend_dropped_total,
            }),
            Self::Ifc => None,
        }
    }
}

#[derive(Debug)]
struct PendingWrite<W> {
    write: W,
    sequence: u64,
    /// When this key's sink copy first fell behind: kept when a newer write
    /// replaces this one, so the age gauge reports staleness, not churn.
    since: Instant,
}

#[derive(Debug)]
struct PendingWrites<K, W> {
    writes: HashMap<K, PendingWrite<W>>,
    /// The earliest `since` in `writes`, so the age gauge needs no scan.
    oldest: Option<Instant>,
}

/// Code a test runs at the start of every enqueue, after the caller took its
/// snapshot and before the write reaches the pending map: where a racing
/// writer can overtake it.
#[cfg(test)]
#[derive(Clone)]
pub(crate) struct EnqueueHook(pub(crate) Arc<dyn Fn() + Send + Sync>);

/// What the handles and the drainer share.
struct Shared<K, W> {
    kind: QueueKind,
    pending: Mutex<PendingWrites<K, W>>,
    /// Signalled on every write; a write landing while the drainer is busy
    /// leaves a permit, so it is never missed.
    wake: Notify,
    /// Writes the drainer has taken out of `pending` and not yet applied.
    held: AtomicUsize,
    /// The drainer is gone: nothing will apply a new write.
    closed: AtomicBool,
    /// The last [`WriteSequence`] handed out.
    sequence: AtomicU64,
    /// When the oldest write still pending at the drainer's last pass first
    /// fell behind: what the oldest-pending gauge reports.
    oldest_published: Mutex<Option<Instant>>,
    #[cfg(test)]
    hook: std::sync::OnceLock<EnqueueHook>,
}

impl<K, W> Shared<K, W> {
    /// The pending map. A panic while it was held cannot leave it torn (every
    /// critical section is one map operation), so poisoning is ignored rather
    /// than turned into a lost write.
    fn pending(&self) -> MutexGuard<'_, PendingWrites<K, W>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The enqueueing side of a queue. Cheap to clone; the drainer runs until
/// every clone is dropped.
pub(crate) struct QueueHandle<K, W> {
    shared: Arc<Shared<K, W>>,
    /// Never sent on: its closing tells the drainer every handle is gone.
    _alive: mpsc::Sender<()>,
}

impl<K, W> Clone for QueueHandle<K, W> {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
            _alive: self._alive.clone(),
        }
    }
}

impl<K, W> std::fmt::Debug for QueueHandle<K, W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueueHandle")
            .field("kind", &self.shared.kind)
            .finish_non_exhaustive()
    }
}

/// A queue for `kind`: the handle to enqueue on and the drainer to run.
pub(crate) fn queue<K, W: QueuedWrite>(kind: QueueKind) -> (QueueHandle<K, W>, Drainer<K, W>) {
    let shared = Arc::new(Shared {
        kind,
        pending: Mutex::new(PendingWrites {
            writes: HashMap::new(),
            oldest: None,
        }),
        wake: Notify::new(),
        held: AtomicUsize::new(0),
        closed: AtomicBool::new(false),
        sequence: AtomicU64::new(0),
        oldest_published: Mutex::new(None),
        #[cfg(test)]
        hook: std::sync::OnceLock::new(),
    });
    let (alive, handles) = mpsc::channel(1);
    (
        QueueHandle {
            shared: Arc::clone(&shared),
            _alive: alive,
        },
        Drainer {
            shared,
            handles,
            backlog: HashMap::new(),
            applied: HashMap::new(),
            pruned_at: Instant::now(),
            backoff: INITIAL_BACKOFF,
            retry_at: None,
        },
    )
}

impl<K: Eq + Hash, W: QueuedWrite> QueueHandle<K, W> {
    /// The next sequence: take it under the lock that orders the snapshot.
    pub(crate) fn sequence(&self) -> WriteSequence {
        WriteSequence(self.shared.sequence.fetch_add(1, Ordering::SeqCst) + 1)
    }

    /// Run `hook` at the start of every later enqueue.
    #[cfg(test)]
    pub(crate) fn set_hook(&self, hook: EnqueueHook) {
        let _ = self.shared.hook.set(hook);
    }

    /// Make `write` the desired state of `key`, unless a newer one (a higher
    /// `sequence`) is already pending.
    ///
    /// Never waits and never drops for lack of room. Only a drainer that is
    /// gone loses a write, and that is counted and logged.
    pub(crate) fn enqueue(&self, key: K, describe: &str, write: W, sequence: WriteSequence) {
        #[cfg(test)]
        if let Some(hook) = self.shared.hook.get() {
            (hook.0)();
        }
        let label = write.label();
        let kind = self.shared.kind;
        if self.shared.closed.load(Ordering::Acquire) {
            tracing::warn!(
                queue = kind.name(),
                command = label,
                key = describe,
                "backend writer task is gone; dropping the write, \
                 so the backend will not match memory after a restart"
            );
            if let Some(metrics) = kind.metrics() {
                metrics.dropped.with_label_values(&[label, "closed"]).inc();
            }
            return;
        }
        let now = Instant::now();
        let (depth, superseded) = {
            let mut pending = self.shared.pending();
            let superseded = match pending.writes.entry(key) {
                Entry::Occupied(mut entry) => {
                    let held = entry.get_mut();
                    if sequence.0 >= held.sequence {
                        held.write = write;
                        held.sequence = sequence.0;
                    }
                    true
                }
                Entry::Vacant(entry) => {
                    entry.insert(PendingWrite {
                        write,
                        sequence: sequence.0,
                        since: now,
                    });
                    false
                }
            };
            pending.oldest.get_or_insert(now);
            (pending.writes.len(), superseded)
        };
        self.shared.wake.notify_one();
        if let Some(metrics) = kind.metrics() {
            if superseded {
                metrics.coalesced.inc();
            }
            let held = self.shared.held.load(Ordering::Relaxed);
            metrics.depth.set(depth.saturating_add(held) as i64);
        }
    }

    /// How long the oldest pending write has waited, as of the drainer's last
    /// pass: what the oldest-pending gauge reports. Zero when caught up.
    #[cfg(test)]
    pub(crate) fn oldest_pending(&self) -> Duration {
        self.shared
            .oldest_published
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .map_or(Duration::ZERO, |since| since.elapsed())
    }

    /// Keys whose latest write has not been applied yet, waiting or in flight.
    #[cfg(test)]
    pub(crate) fn pending_writes(&self) -> usize {
        self.shared.pending().writes.len() + self.shared.held.load(Ordering::SeqCst)
    }

    /// The write pending for `key`, if any, through `read`.
    #[cfg(test)]
    pub(crate) fn inspect<T>(&self, key: &K, read: impl FnOnce(Option<&W>) -> T) -> T {
        read(
            self.shared
                .pending()
                .writes
                .get(key)
                .map(|held| &held.write),
        )
    }
}

/// What woke a drainer waiting with [`Drainer::next_event`].
pub(crate) enum DrainEvent {
    /// A write arrived.
    Write,
    /// A retry is due.
    Retry,
    /// Every handle is gone.
    Closed,
}

/// The draining side of a queue, run by one task.
pub(crate) struct Drainer<K, W: QueuedWrite> {
    shared: Arc<Shared<K, W>>,
    handles: mpsc::Receiver<()>,
    /// Writes taken out of the shared map and not yet applied. Only the
    /// drainer touches it, so the enqueue lock is held for a swap, never for a
    /// round trip to the sink.
    backlog: HashMap<K, PendingWrite<W>>,
    /// The sequence of each write applied in the last [`APPLIED_RETENTION`].
    applied: HashMap<K, (u64, Instant)>,
    pruned_at: Instant,
    /// The delay before the next retry, doubled per failed attempt.
    backoff: Duration,
    /// Set while backing off: when the next attempt is due.
    retry_at: Option<tokio::time::Instant>,
}

impl<K, W> Drainer<K, W>
where
    K: Eq + Hash + Clone + Send + Sync + std::fmt::Display + 'static,
    W: QueuedWrite,
{
    /// Wait for the next thing to do: a write, a due retry, or every handle
    /// gone. A write does not wake a drainer that is backing off.
    pub(crate) async fn next_event(&mut self) -> DrainEvent {
        let retry_at = self.retry_at;
        tokio::select! {
            biased;
            alive = self.handles.recv() => match alive {
                None => DrainEvent::Closed,
                Some(()) => DrainEvent::Write,
            },
            _ = sleep_until(retry_at), if retry_at.is_some() => {
                self.retry_at = None;
                DrainEvent::Retry
            }
            _ = self.shared.wake.notified(), if retry_at.is_none() => DrainEvent::Write,
        }
    }

    /// Apply everything pending, unless a retry is not due yet. A failure
    /// keeps the writes and schedules the retry.
    pub(crate) async fn attempt<S: WriteSink<K, W>>(&mut self, sink: &S) {
        if self.retry_at.is_some() {
            return;
        }
        match self.flush(sink).await {
            Ok(()) => self.backoff = INITIAL_BACKOFF,
            Err(error) => {
                tracing::warn!(
                    queue = self.shared.kind.name(),
                    %error,
                    pending = self.backlog.len(),
                    retry_in_ms = self.backoff.as_millis() as u64,
                    "backend write-through failed; keeping the writes and retrying"
                );
                self.retry_at = Some(tokio::time::Instant::now() + self.backoff);
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            }
        }
        self.publish();
    }

    /// One last attempt, retry or not, when every handle is gone.
    pub(crate) async fn finish<S: WriteSink<K, W>>(&mut self, sink: &S) {
        self.retry_at = None;
        self.attempt(sink).await;
    }

    /// Move the shared map's writes into the backlog. The newer of two writes
    /// to one key wins, and a write older than one already applied is stale.
    fn absorb(&mut self) {
        let taken = {
            let mut pending = self.shared.pending();
            pending.oldest = None;
            std::mem::take(&mut pending.writes)
        };
        let now = Instant::now();
        if now.duration_since(self.pruned_at) >= Duration::from_secs(1) {
            self.applied
                .retain(|_, (_, at)| now.duration_since(*at) < APPLIED_RETENTION);
            if self.applied.is_empty() && self.applied.capacity() > BACKLOG_RETAINED_CAPACITY {
                self.applied = HashMap::new();
            }
            self.pruned_at = now;
        }
        for (key, write) in taken {
            if let Some((applied, _)) = self.applied.get(&key) {
                if *applied > write.sequence {
                    tracing::debug!(
                        queue = self.shared.kind.name(),
                        key = %key,
                        "discarding a write older than one already applied"
                    );
                    continue;
                }
            }
            match self.backlog.entry(key) {
                Entry::Occupied(mut entry) => {
                    let held = entry.get_mut();
                    if write.sequence >= held.sequence {
                        held.write = write.write;
                        held.sequence = write.sequence;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(write);
                }
            }
        }
        self.shared.held.store(self.backlog.len(), Ordering::SeqCst);
    }

    /// Apply the backlog in concurrent batches.
    ///
    /// A write the sink refuses goes back in the backlog for the next attempt,
    /// and the attempt reports the error. A batch in which nothing succeeded
    /// means the sink is down, so the attempt stops there rather than spend an
    /// operation timeout on every remaining batch; a batch in which some writes
    /// succeeded means the sink is up and those keys are the problem, so the
    /// rest of the backlog still goes.
    async fn flush<S: WriteSink<K, W>>(&mut self, sink: &S) -> Result<(), BackendError> {
        self.absorb();
        let mut refused = Vec::new();
        let mut last_error = None;
        while !self.backlog.is_empty() {
            let keys: Vec<K> = self
                .backlog
                .keys()
                .take(WRITE_CONCURRENCY)
                .cloned()
                .collect();
            let batch: Vec<(K, PendingWrite<W>)> = keys
                .iter()
                .filter_map(|key| self.backlog.remove_entry(key))
                .collect();
            let writes: Vec<(&K, &W)> =
                batch.iter().map(|(key, held)| (key, &held.write)).collect();
            let mut results = sink.apply_batch(&writes).await;
            drop(writes);
            // A sink that answered for fewer writes than it was given has not
            // applied the rest: they stay pending.
            results.resize_with(batch.len(), || {
                Err(BackendError::Query(
                    "the backend returned no result for this write".to_string(),
                ))
            });
            let mut succeeded = 0usize;
            let now = Instant::now();
            for ((key, held), result) in batch.into_iter().zip(results) {
                match result {
                    Ok(()) => {
                        succeeded += 1;
                        self.applied.insert(key, (held.sequence, now));
                    }
                    // Retrying an encoding failure fails the same way forever.
                    Err(BackendError::Serialization(error)) => {
                        let label = held.write.label();
                        tracing::error!(
                            queue = self.shared.kind.name(),
                            key = %key,
                            command = label,
                            %error,
                            "backend cannot encode the write; dropping it"
                        );
                        if let Some(metrics) = self.shared.kind.metrics() {
                            metrics
                                .dropped
                                .with_label_values(&[label, "unencodable"])
                                .inc();
                        }
                    }
                    Err(error) => {
                        refused.push((key, held));
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

    /// The pending count and the age of the oldest pending write.
    fn publish(&self) {
        let (waiting, shared_oldest) = {
            let pending = self.shared.pending();
            (pending.writes.len(), pending.oldest)
        };
        // A scan, but of a backlog that is empty unless the sink is refusing
        // writes, and then at most once per retry.
        let oldest = self
            .backlog
            .values()
            .map(|held| held.since)
            .chain(shared_oldest)
            .min();
        *self
            .shared
            .oldest_published
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = oldest;
        let Some(metrics) = self.shared.kind.metrics() else {
            return;
        };
        metrics
            .depth
            .set(waiting.saturating_add(self.backlog.len()) as i64);
        metrics
            .oldest
            .set(oldest.map_or(0, |since| since.elapsed().as_secs()) as i64);
    }
}

impl<K, W: QueuedWrite> Drop for Drainer<K, W> {
    /// However the drainer ends (every handle dropped, a panic, the runtime
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
            queue = self.shared.kind.name(),
            lost,
            "backend writer stopped with write-throughs not applied; \
             the backend will not match memory after a restart"
        );
        if let Some(metrics) = self.shared.kind.metrics() {
            for held in left.values().chain(self.backlog.values()) {
                metrics
                    .dropped
                    .with_label_values(&[held.write.label(), "closed"])
                    .inc();
            }
            metrics.depth.set(0);
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
