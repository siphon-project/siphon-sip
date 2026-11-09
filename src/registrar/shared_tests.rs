//! Two registrar nodes over one shared store: what one writes the other reads,
//! and an expiry is announced once.
//!
//! The store is the in-memory backend behind an `Arc`, so these run without a
//! server; `backend::redis_store_tests` runs the same scenario against Redis
//! when `SIPHON_TEST_REDIS_URL` is set.

use std::sync::Arc;
use std::time::Duration;

use super::backend::{
    spawn_backend_writer, BackendError, MemoryBackend, RegistrarBackend, StoredAorState,
    StoredContact,
};
use super::*;
use crate::sip::uri::SipUri;

const AOR: &str = "sip:alice@ims.example.invalid";

fn contact(host: &str) -> SipUri {
    SipUri::new(host.to_string()).with_user("alice".to_string())
}

/// A node with its own memory, writing to and reading through `store`.
fn node<B: RegistrarBackend + 'static>(
    store: &Arc<B>,
    name: &str,
    freshness_ms: u64,
) -> Arc<Registrar> {
    let registrar = Arc::new(Registrar::new(RegistrarConfig {
        min_expires: 1,
        ..RegistrarConfig::default()
    }));
    registrar.set_instance_identity(InstanceIdentity {
        id: name.to_string(),
        epoch: format!("{name}-epoch"),
    });
    registrar.set_backend_writer(spawn_backend_writer(Arc::clone(store)));
    registrar.set_shared_reader(SharedReader::new(
        Arc::clone(store),
        Duration::from_millis(freshness_ms),
    ));
    registrar
}

fn register(registrar: &Registrar, host: &str, expires: u32, cseq: u32) {
    registrar
        .save(
            AOR,
            contact(host),
            expires,
            1.0,
            "call-alice".to_string(),
            cseq,
        )
        .expect("save");
}

/// Wait until the node's write-through has reached the store.
async fn settled(registrar: &Registrar) {
    for _ in 0..200 {
        let pending = registrar
            .backend_writer
            .get()
            .is_some_and(|writer| writer.has_pending(AOR));
        if !pending {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the write-through never reached the store");
}

fn expired_events(receiver: &mut broadcast::Receiver<RegistrationEvent>) -> usize {
    let mut seen = 0;
    while let Ok(event) = receiver.try_recv() {
        if matches!(event, RegistrationEvent::Expired { .. }) {
            seen += 1;
        }
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_binding_written_on_one_node_is_found_on_another() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 1000), node(&store, "b", 1000));
    assert!(!b.is_registered(AOR), "nothing registered yet");
    // Not cached as a miss for longer than the window.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    register(&a, "198.51.100.10", 3600, 1);
    settled(&a).await;

    let found = b.lookup(AOR);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].uri.host, "198.51.100.10");
    assert!(b.is_registered(AOR));
    assert!(b.registered_aor(AOR).is_some());
    assert!(
        !b.is_local_contact(&found[0]),
        "the binding another node accepted is not this node's own"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deregistration_on_one_node_disappears_on_another_within_the_window() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 100), node(&store, "b", 100));
    register(&a, "198.51.100.10", 3600, 1);
    settled(&a).await;
    assert!(b.is_registered(AOR));

    a.remove_all(AOR);
    settled(&a).await;
    // Inside the window the node still answers from its copy.
    assert!(
        b.is_registered(AOR),
        "served from the cache inside the window"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!b.is_registered(AOR), "gone once the window passed");
    assert!(b.lookup(AOR).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_and_a_second_binding_written_on_one_node_reach_another() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 50), node(&store, "b", 50));
    register(&a, "198.51.100.10", 3600, 1);
    settled(&a).await;
    assert_eq!(b.lookup(AOR).len(), 1);

    a.save(
        AOR,
        contact("198.51.100.11"),
        3600,
        0.5,
        "call-other".to_string(),
        1,
    )
    .expect("save");
    settled(&a).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    let hosts: Vec<String> = b.lookup(AOR).iter().map(|c| c.uri.host.clone()).collect();
    assert_eq!(hosts, vec!["198.51.100.10", "198.51.100.11"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_alias_of_the_implicit_set_resolves_on_a_node_that_never_saw_the_primary() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 1000), node(&store, "b", 1000));
    register(&a, "198.51.100.10", 3600, 1);
    a.set_associated_uris(AOR, vec!["tel:+15550100".to_string()]);
    settled(&a).await;

    assert!(b.is_registered("tel:+15550100"));
    assert_eq!(b.lookup("tel:+15550100").len(), 1);
    assert_eq!(b.associated_uris(AOR), vec!["tel:+15550100".to_string()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_alias_the_primary_does_not_list_is_not_followed() {
    let store = Arc::new(MemoryBackend::new());
    let b = node(&store, "b", 1000);
    store
        .save_aor_state(
            "sip:other@ims.example.invalid",
            &StoredAorState {
                associated_uris: vec!["tel:+15550199".to_string()],
                ..StoredAorState::default()
            },
        )
        .await
        .expect("state");
    assert!(!b.is_registered("tel:+15550100"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expiry_seen_by_two_nodes_is_announced_once() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 1000), node(&store, "b", 1000));
    let (mut a_events, mut b_events) = (a.subscribe_events(), b.subscribe_events());
    register(&a, "198.51.100.10", 2, 1);
    settled(&a).await;
    assert!(b.is_registered(AOR), "b caches the binding");

    tokio::time::sleep(Duration::from_millis(2300)).await;
    a.expire_stale();
    b.expire_stale();

    assert_eq!(
        expired_events(&mut a_events) + expired_events(&mut b_events),
        1,
        "exactly one node announces the expiry"
    );
    assert!(!a.is_registered(AOR) && !b.is_registered(AOR));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_does_not_announce_the_expiry_of_a_binding_another_node_refreshed() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 1000), node(&store, "b", 1000));
    let mut b_events = b.subscribe_events();
    register(&a, "198.51.100.10", 2, 1);
    settled(&a).await;
    assert!(b.is_registered(AOR));

    register(&a, "198.51.100.10", 3600, 2);
    settled(&a).await;
    tokio::time::sleep(Duration::from_millis(2300)).await;

    assert_eq!(b.expire_stale(), 0);
    assert_eq!(expired_events(&mut b_events), 0);
    assert!(
        b.lookup(AOR).iter().any(|c| c.uri.host == "198.51.100.10"),
        "the refreshed binding is still served"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_shared_reader_a_node_sees_only_its_own_memory() {
    let store = Arc::new(MemoryBackend::new());
    let (a, b) = (node(&store, "a", 1000), {
        // Same store for write-through, no read-through.
        let registrar = Arc::new(Registrar::new(RegistrarConfig {
            min_expires: 1,
            ..RegistrarConfig::default()
        }));
        registrar.set_backend_writer(spawn_backend_writer(Arc::clone(&store)));
        registrar
    });
    register(&a, "198.51.100.10", 3600, 1);
    settled(&a).await;
    assert!(!b.is_registered(AOR));
    assert!(b.lookup(AOR).is_empty());

    let mut events = b.subscribe_events();
    register(&b, "198.51.100.20", 1, 1);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(b.expire_stale(), 1);
    assert_eq!(
        expired_events(&mut events),
        1,
        "a lone node owns every expiry"
    );
}

/// A store whose writes take a while to land.
#[derive(Debug)]
struct SlowStore(MemoryBackend);

impl RegistrarBackend for SlowStore {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        tokio::time::sleep(Duration::from_millis(400)).await;
        self.0.save(aor, contacts).await
    }
    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        self.0.load(aor).await
    }
    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        self.0.remove(aor).await
    }
    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        self.0.exists(aor).await
    }
    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        self.0.all_aors().await
    }
    async fn save_aor_state(&self, aor: &str, state: &StoredAorState) -> Result<(), BackendError> {
        self.0.save_aor_state(aor, state).await
    }
    async fn load_aor_state(&self, aor: &str) -> Result<Option<StoredAorState>, BackendError> {
        self.0.load_aor_state(aor).await
    }
    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        self.0.remove_aor_state(aor).await
    }
    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        self.0.all_aor_state_aors().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_reads_its_own_write_while_the_store_has_not_caught_up() {
    let store = Arc::new(SlowStore(MemoryBackend::new()));
    let a = node(&store, "a", 0);
    register(&a, "198.51.100.10", 3600, 1);
    // The store is still empty: a read-through must not erase the binding.
    assert!(a.is_registered(AOR));
    assert_eq!(a.lookup(AOR).len(), 1);
    settled(&a).await;
    assert_eq!(a.lookup(AOR).len(), 1);
}

/// A store whose reads return what it held when they started, late, and
/// whose writes land while a read is out.
#[derive(Debug)]
struct SlowRead(MemoryBackend);

impl RegistrarBackend for SlowRead {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.0.save(aor, contacts).await
    }
    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        let held = self.0.load(aor).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        held
    }
    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        self.0.remove(aor).await
    }
    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        self.0.exists(aor).await
    }
    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        self.0.all_aors().await
    }
    async fn save_aor_state(&self, aor: &str, state: &StoredAorState) -> Result<(), BackendError> {
        self.0.save_aor_state(aor, state).await
    }
    async fn load_aor_state(&self, aor: &str) -> Result<Option<StoredAorState>, BackendError> {
        self.0.load_aor_state(aor).await
    }
    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        self.0.remove_aor_state(aor).await
    }
    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        self.0.all_aor_state_aors().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_started_before_the_nodes_write_landed_does_not_erase_it() {
    let store = Arc::new(SlowRead(MemoryBackend::new()));
    let a = node(&store, "a", 0);
    // The write is queued; a read starts while it is, takes the store's older
    // answer, and returns after the write has landed.
    register(&a, "198.51.100.10", 3600, 1);
    let reader = {
        let a = Arc::clone(&a);
        tokio::task::spawn_blocking(move || a.is_registered(AOR))
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    settled(&a).await;
    let _ = reader.await;
    // Past the read: the node's copy is its own write, not the older store.
    assert!(a.bindings.contains_key(AOR), "the read erased the write");
}

/// A store that cannot be read.
#[derive(Debug)]
struct Unreadable(MemoryBackend);

impl RegistrarBackend for Unreadable {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        self.0.save(aor, contacts).await
    }
    async fn load(&self, _aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        Err(BackendError::Connection("down".to_string()))
    }
    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        self.0.remove(aor).await
    }
    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        self.0.exists(aor).await
    }
    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        self.0.all_aors().await
    }
    async fn save_aor_state(&self, aor: &str, state: &StoredAorState) -> Result<(), BackendError> {
        self.0.save_aor_state(aor, state).await
    }
    async fn load_aor_state(&self, aor: &str) -> Result<Option<StoredAorState>, BackendError> {
        self.0.load_aor_state(aor).await
    }
    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        self.0.remove_aor_state(aor).await
    }
    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        self.0.all_aor_state_aors().await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreadable_store_degrades_a_lookup_to_the_local_copy() {
    let store = Arc::new(Unreadable(MemoryBackend::new()));
    let a = node(&store, "a", 1000);
    register(&a, "198.51.100.10", 3600, 1);
    settled(&a).await;
    assert!(a.is_registered(AOR));
    assert_eq!(a.lookup(AOR).len(), 1);
}
