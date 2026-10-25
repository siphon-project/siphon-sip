//! The write-through path end to end: a registrar, the writer task, and a
//! backend slow or down enough that the writes outrun it.
//!
//! Every test ends the same way, by waiting until the backend holds exactly
//! what the registrar holds in memory. That is the property the writer exists
//! for: a write that never reaches the backend is a binding a restart brings
//! back (a delete) or loses (a save).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::super::tests::sample_stored_contact;
use super::*;
use crate::registrar::backend::{restore_from_backend, MemoryBackend};
use crate::registrar::Registrar;
use crate::sip::uri::SipUri;

/// A backend in front of a [`MemoryBackend`] the test keeps a handle to, whose
/// writes each take `delay` and fail while `down` is set.
#[derive(Debug, Clone)]
struct SlowBackend {
    inner: Arc<MemoryBackend>,
    delay: Duration,
    down: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
}

impl SlowBackend {
    fn new(inner: Arc<MemoryBackend>, delay: Duration) -> Self {
        Self {
            inner,
            delay,
            down: Arc::new(AtomicBool::new(false)),
            writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn write(&self) -> Result<(), BackendError> {
        tokio::time::sleep(self.delay).await;
        if self.down.load(Ordering::SeqCst) {
            return Err(BackendError::Connection("connection refused".to_string()));
        }
        self.writes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl RegistrarBackend for SlowBackend {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        self.write().await?;
        self.inner.save(aor, contacts).await
    }
    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        self.inner.load(aor).await
    }
    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        self.write().await?;
        self.inner.remove(aor).await
    }
    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        self.inner.exists(aor).await
    }
    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        self.inner.all_aors().await
    }
    async fn save_aor_state(&self, aor: &str, state: &StoredAorState) -> Result<(), BackendError> {
        self.write().await?;
        self.inner.save_aor_state(aor, state).await
    }
    async fn load_aor_state(&self, aor: &str) -> Result<Option<StoredAorState>, BackendError> {
        self.inner.load_aor_state(aor).await
    }
    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        self.write().await?;
        self.inner.remove_aor_state(aor).await
    }
    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        self.inner.all_aor_state_aors().await
    }
}

fn aor(index: usize) -> String {
    format!("sip:001010{index:09}@ims.example.com")
}

fn route() -> Vec<String> {
    vec!["<sip:orig@scscf.ims.example.com;lr>".to_string()]
}

fn save(registrar: &Registrar, aor: &str, host: &str) {
    registrar
        .save(
            aor,
            SipUri::new(host.to_string()).with_user("ue".to_string()),
            3600,
            1.0,
            format!("call-{aor}-{host}"),
            1,
        )
        .expect("save");
}

/// A backend holding `count` AoRs, one binding and a Service-Route each:
/// what a P-CSCF restarts into.
async fn seeded(count: usize) -> Arc<MemoryBackend> {
    let store = Arc::new(MemoryBackend::new());
    let contact = sample_stored_contact();
    let state = StoredAorState {
        service_routes: route(),
        ..Default::default()
    };
    for index in 0..count {
        store
            .save(&aor(index), std::slice::from_ref(&contact))
            .await
            .expect("seed");
        store
            .save_aor_state(&aor(index), &state)
            .await
            .expect("seed");
    }
    store
}

/// Where the backend and the registrar disagree, or `None` once they agree:
/// the same AoRs with the same contact URIs, and the same Service-Routes.
async fn divergence<B: RegistrarBackend>(store: &B, registrar: &Registrar) -> Option<String> {
    let mut memory: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for aor in registrar.registered_aors() {
        let uris = registrar
            .lookup_all(&aor)
            .iter()
            .map(|contact| contact.uri.to_string())
            .collect();
        memory.insert(aor, uris);
    }
    let mut stored: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for aor in store.all_aors().await.expect("all_aors") {
        let uris = store
            .load(&aor)
            .await
            .expect("load")
            .into_iter()
            .map(|contact| contact.uri)
            .collect();
        stored.insert(aor, uris);
    }
    if memory != stored {
        let missing = memory
            .keys()
            .filter(|aor| !stored.contains_key(*aor))
            .count();
        let extra = stored
            .keys()
            .filter(|aor| !memory.contains_key(*aor))
            .count();
        let differing = memory
            .iter()
            .find(|(aor, uris)| stored.get(*aor).is_some_and(|held| held != *uris))
            .map(|(aor, uris)| format!("; {aor}: {uris:?} in memory, {:?} stored", stored[aor]))
            .unwrap_or_default();
        return Some(format!(
            "bindings: {} in memory, {} in the backend ({missing} missing, {extra} extra){differing}",
            memory.len(),
            stored.len()
        ));
    }
    let stated: BTreeSet<String> = store
        .all_aor_state_aors()
        .await
        .expect("state aors")
        .into_iter()
        .collect();
    let mut aors: BTreeSet<String> = memory.into_keys().collect();
    aors.extend(stated.iter().cloned());
    for aor in aors {
        let in_memory = registrar.service_routes(&aor);
        let in_backend = store
            .load_aor_state(&aor)
            .await
            .expect("load state")
            .map(|state| state.service_routes)
            .unwrap_or_default();
        if in_memory != in_backend {
            return Some(format!(
                "state of {aor}: {in_memory:?} in memory, {in_backend:?} in the backend"
            ));
        }
    }
    None
}

/// Wait (in paused time) until the backend matches memory, or fail with how
/// it still differs.
async fn converged<B: RegistrarBackend>(store: &B, registrar: &Registrar) {
    let mut last = None;
    for _ in 0..600 {
        last = divergence(store, registrar).await;
        if last.is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the backend never caught up with memory: {last:?}");
}

/// The restart the field reported: thousands of restored bindings evicted in
/// one go, two backend writes each (the binding and its Service-Route), into a
/// backend that drains far slower than the eviction issues them. Every delete
/// must land, or the next restore brings the binding back.
#[tokio::test(start_paused = true)]
async fn a_restore_eviction_burst_reaches_the_backend_in_full() {
    const BINDINGS: usize = 10_000;
    let store = seeded(BINDINGS).await;
    let registrar = Registrar::default();
    restore_from_backend(&*store, &registrar)
        .await
        .expect("restore");
    assert_eq!(registrar.aor_count(), BINDINGS);
    registrar.set_backend_writer(spawn_backend_writer(SlowBackend::new(
        Arc::clone(&store),
        Duration::from_millis(1),
    )));

    let evicted = registrar.evict_restored(|_| true);

    assert_eq!(evicted.len(), BINDINGS);
    converged(&*store, &registrar).await;
    assert!(store.all_aors().await.expect("aors").is_empty());
    assert!(store.all_aor_state_aors().await.expect("state").is_empty());
}

/// REGISTERs arriving while the eviction runs persist like any other: the
/// burst must not crowd them out.
#[tokio::test(start_paused = true)]
async fn saves_during_the_eviction_burst_all_persist() {
    const BINDINGS: usize = 10_000;
    const THREADS: usize = 4;
    const SAVES_PER_THREAD: usize = 500;
    let store = seeded(BINDINGS).await;
    let registrar = Registrar::default();
    restore_from_backend(&*store, &registrar)
        .await
        .expect("restore");
    registrar.set_backend_writer(spawn_backend_writer(SlowBackend::new(
        Arc::clone(&store),
        Duration::from_millis(1),
    )));

    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            let registrar = &registrar;
            scope.spawn(move || {
                for index in 0..SAVES_PER_THREAD {
                    let fresh = aor(BINDINGS + thread * SAVES_PER_THREAD + index);
                    save(registrar, &fresh, "198.51.100.20");
                    registrar.set_service_routes(&fresh, route());
                }
            });
        }
        // Only the restored bindings: the fresh ones carry no flow and the
        // selector skips them, as the IPsec restore skips a live SA.
        registrar.evict_restored(|contact| contact.uri.host == "10.0.0.1");
    });

    assert_eq!(registrar.aor_count(), THREADS * SAVES_PER_THREAD);
    converged(&*store, &registrar).await;
    assert_eq!(
        store.all_aors().await.expect("aors").len(),
        THREADS * SAVES_PER_THREAD
    );
}

/// A delete then a save of the same AoR ends as the save, and a save then a
/// delete ends as the delete, however the writer happens to batch them.
#[tokio::test(start_paused = true)]
async fn the_last_write_to_an_aor_is_the_one_that_lands() {
    let store = Arc::new(MemoryBackend::new());
    let registrar = Registrar::default();
    registrar.set_backend_writer(spawn_backend_writer(SlowBackend::new(
        Arc::clone(&store),
        Duration::from_millis(50),
    )));
    let deleted_then_saved = aor(1);
    let saved_then_deleted = aor(2);

    save(&registrar, &deleted_then_saved, "198.51.100.1");
    save(&registrar, &saved_then_deleted, "198.51.100.2");
    // Let the writer take both and be mid-write when the next ones land.
    tokio::time::sleep(Duration::from_millis(10)).await;
    registrar.remove_all(&deleted_then_saved);
    save(&registrar, &deleted_then_saved, "198.51.100.3");
    registrar.remove_all(&saved_then_deleted);

    converged(&*store, &registrar).await;
    let stored = store.load(&deleted_then_saved).await.expect("load");
    assert_eq!(stored.len(), 1);
    assert!(stored[0].uri.contains("198.51.100.3"), "{stored:?}");
    assert!(!store.exists(&saved_then_deleted).await.expect("exists"));

    // And straight after each other, with nothing in between.
    registrar.remove_all(&deleted_then_saved);
    save(&registrar, &deleted_then_saved, "198.51.100.4");
    save(&registrar, &saved_then_deleted, "198.51.100.5");
    registrar.remove_all(&saved_then_deleted);
    converged(&*store, &registrar).await;
    assert!(store.load(&deleted_then_saved).await.expect("load")[0]
        .uri
        .contains("198.51.100.4"));
    assert!(!store.exists(&saved_then_deleted).await.expect("exists"));
}

/// A backend outage holds the writes rather than losing them, and the writer
/// drains them once the backend answers again.
#[tokio::test(start_paused = true)]
async fn writes_during_an_outage_drain_once_the_backend_recovers() {
    let store = Arc::new(MemoryBackend::new());
    let backend = SlowBackend::new(Arc::clone(&store), Duration::from_millis(1));
    let down = Arc::clone(&backend.down);
    let registrar = Registrar::default();
    let writer = spawn_backend_writer(backend);
    registrar.set_backend_writer(writer.clone());

    down.store(true, Ordering::SeqCst);
    for index in 0..200 {
        save(&registrar, &aor(index), "198.51.100.30");
        registrar.set_service_routes(&aor(index), route());
    }
    for index in 0..50 {
        registrar.remove_all(&aor(index));
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(
        store.all_aors().await.expect("aors").is_empty(),
        "nothing reaches a backend that is down"
    );
    // What the oldest-pending gauge reports (wall-clock, so not the paused
    // test clock): non-zero while the writes are stuck.
    assert!(writer.oldest_pending() > Duration::ZERO);

    down.store(false, Ordering::SeqCst);
    converged(&*store, &registrar).await;
    assert_eq!(store.all_aors().await.expect("aors").len(), 150);
    for _ in 0..100 {
        if writer.pending_writes() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        writer.oldest_pending(),
        Duration::ZERO,
        "the gauge drops back"
    );
}

/// The per-module leak gate: after complete save/de-register cycles the
/// pending map and the writer's backlog hold nothing. An entry that outlived
/// its write would be the classic per-call leak, and a writer stuck holding one
/// would be a binding whose backend copy is never corrected.
#[tokio::test(start_paused = true)]
async fn the_pending_writes_drain_to_zero_after_complete_cycles() {
    const AORS: usize = 5_000;
    let store = Arc::new(MemoryBackend::new());
    let writer = spawn_backend_writer(SlowBackend::new(
        Arc::clone(&store),
        Duration::from_millis(1),
    ));
    let registrar = Registrar::default();
    registrar.set_backend_writer(writer.clone());

    for _cycle in 0..3 {
        for index in 0..AORS {
            save(&registrar, &aor(index), "198.51.100.40");
            registrar.set_service_routes(&aor(index), route());
        }
        assert!(writer.pending_writes() > 0, "the cycle issued writes");
        for index in 0..AORS {
            registrar.remove_all(&aor(index));
        }
        converged(&*store, &registrar).await;
        for _ in 0..100 {
            if writer.pending_writes() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(writer.pending_writes(), 0);
    }
    assert!(store.all_aors().await.expect("aors").is_empty());
    assert!(store.all_aor_state_aors().await.expect("state").is_empty());
}

/// The same restart against a real Redis: the eviction burst and the saves
/// that race it go through the writer's concurrent batches, and Redis ends
/// holding exactly the registrar's state (hash, index and state key).
#[cfg(feature = "redis-backend")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_eviction_burst_through_the_writer_reaches_redis_in_full() {
    use crate::registrar::backend::{RedisBackend, RedisBackendConfig};
    let url = match std::env::var("SIPHON_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("skipped: SIPHON_TEST_REDIS_URL is not set");
            return;
        }
    };
    const BINDINGS: usize = 10_000;
    const FRESH: usize = 1_000;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let config = RedisBackendConfig {
        url,
        key_prefix: format!("siphon-test:writer-burst:{}:{nanos}:", std::process::id()),
        ..RedisBackendConfig::default()
    };
    let redis = RedisBackend::connect(config.clone())
        .await
        .expect("connect to the test Redis");
    let contact = sample_stored_contact();
    let state = StoredAorState {
        service_routes: route(),
        ..Default::default()
    };
    for index in 0..BINDINGS {
        redis
            .save(&aor(index), std::slice::from_ref(&contact))
            .await
            .expect("seed");
        redis
            .save_aor_state(&aor(index), &state)
            .await
            .expect("seed");
    }
    let registrar = Registrar::default();
    restore_from_backend(&redis, &registrar)
        .await
        .expect("restore");
    assert_eq!(registrar.aor_count(), BINDINGS);
    let writer = spawn_backend_writer(
        RedisBackend::connect(config)
            .await
            .expect("connect to the test Redis"),
    );
    registrar.set_backend_writer(writer.clone());

    std::thread::scope(|scope| {
        let registrar = &registrar;
        scope.spawn(move || {
            for index in 0..FRESH {
                let fresh = aor(BINDINGS + index);
                save(registrar, &fresh, "198.51.100.50");
                registrar.set_service_routes(&fresh, route());
            }
        });
        registrar.evict_restored(|contact| contact.uri.host == "10.0.0.1");
    });

    converged(&redis, &registrar).await;
    assert_eq!(redis.count_aors().await.expect("count"), FRESH);
    for _ in 0..100 {
        if writer.pending_writes() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(writer.pending_writes(), 0);
}

/// And against a real Postgres, whose save is several statements per AoR.
#[cfg(feature = "postgres-backend")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_eviction_burst_through_the_writer_reaches_postgres_in_full() {
    use crate::registrar::backend::{PostgresBackend, PostgresBackendConfig};
    let url = match std::env::var("SIPHON_TEST_POSTGRES_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("skipped: SIPHON_TEST_POSTGRES_URL is not set");
            return;
        }
    };
    const BINDINGS: usize = 2_000;
    const FRESH: usize = 200;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let config = PostgresBackendConfig {
        url,
        table: format!("registrar_test_writer_burst_{}_{nanos}", std::process::id()),
        ..PostgresBackendConfig::default()
    };
    let postgres = PostgresBackend::connect(config.clone())
        .await
        .expect("connect to the test Postgres");
    let contact = sample_stored_contact();
    let state = StoredAorState {
        service_routes: route(),
        ..Default::default()
    };
    for index in 0..BINDINGS {
        postgres
            .save(&aor(index), std::slice::from_ref(&contact))
            .await
            .expect("seed");
        postgres
            .save_aor_state(&aor(index), &state)
            .await
            .expect("seed");
    }
    let registrar = Registrar::default();
    restore_from_backend(&postgres, &registrar)
        .await
        .expect("restore");
    let writer = spawn_backend_writer(
        PostgresBackend::connect(config.clone())
            .await
            .expect("connect to the test Postgres"),
    );
    registrar.set_backend_writer(writer.clone());

    std::thread::scope(|scope| {
        let registrar = &registrar;
        scope.spawn(move || {
            for index in 0..FRESH {
                let fresh = aor(BINDINGS + index);
                save(registrar, &fresh, "198.51.100.60");
                registrar.set_service_routes(&fresh, route());
            }
        });
        registrar.evict_restored(|contact| contact.uri.host == "10.0.0.1");
    });

    converged(&postgres, &registrar).await;
    assert_eq!(postgres.count_aors().await.expect("count"), FRESH);
    assert_eq!(writer.pending_writes(), 0);
    let (client, connection) = tokio_postgres::connect(&config.url, tokio_postgres::NoTls)
        .await
        .expect("connect to the test Postgres");
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {table}; DROP TABLE IF EXISTS {table}_aor_state;",
            table = config.table
        ))
        .await
        .expect("drop test tables");
}

/// Two saves of one AoR race: the first takes its snapshot under the AoR's
/// lock, then is held up before its write reaches the writer, while the second
/// takes a newer snapshot and gets its write in first. The older snapshot must
/// not end up in the backend, whether it arrives while the newer write still
/// waits or after the newer write was applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_save_overtaken_before_its_write_is_queued_never_lands_last() {
    const RACED: &str = "sip:001010000000077@ims.example.com";
    for newer_applied_first in [false, true] {
        let store = Arc::new(MemoryBackend::new());
        let (arrived, arrival) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let arrived = std::sync::Mutex::new(arrived);
        let released = std::sync::Mutex::new(released);
        let held_once = AtomicBool::new(false);
        let hook = EnqueueHook(Arc::new(move || {
            if std::thread::current().name() == Some("overtaken")
                && !held_once.swap(true, Ordering::SeqCst)
            {
                let _ = arrived.lock().expect("arrived").send(());
                let _ = released.lock().expect("released").recv();
            }
        }));
        let registrar = Arc::new(Registrar::default());
        registrar.set_backend_writer(spawn_backend_writer_with_hook(
            SlowBackend::new(Arc::clone(&store), Duration::ZERO),
            hook,
        ));

        let overtaken = std::thread::Builder::new()
            .name("overtaken".to_string())
            .spawn({
                let registrar = Arc::clone(&registrar);
                move || save(&registrar, RACED, "198.51.100.71")
            })
            .expect("spawn");
        arrival.recv().expect("the first save took its snapshot");
        save(&registrar, RACED, "198.51.100.72");
        if newer_applied_first {
            for _ in 0..500 {
                if store.load(RACED).await.expect("load").len() == 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(store.load(RACED).await.expect("load").len(), 2);
        }
        release.send(()).expect("release");
        overtaken.join().expect("the first save");

        assert_eq!(registrar.lookup_all(RACED).len(), 2);
        // Give a stale write the time to land if it is going to.
        tokio::time::sleep(Duration::from_millis(200)).await;
        if let Some(divergence) = divergence(&*store, &registrar).await {
            panic!("newer applied first: {newer_applied_first}: {divergence}");
        }
    }
}
