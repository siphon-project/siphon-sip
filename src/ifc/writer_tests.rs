//! The iFC store's write-through against a sink the test controls: slow, or
//! down, so the writes outrun it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::registrar::backend::coalesce::WriteSink;
use crate::registrar::backend::BackendError;

const PROFILE: &str = concat!(
    "<ServiceProfile><InitialFilterCriteria><Priority>0</Priority>",
    "<TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF><SPT>",
    "<ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method>",
    "</SPT></TriggerPoint><ApplicationServer><ServerName>sip:mmtel@example.com</ServerName>",
    "<DefaultHandling>0</DefaultHandling></ApplicationServer></InitialFilterCriteria>",
    "</ServiceProfile>",
);

/// Profiles by AoR, as a Redis would hold them; each write takes `delay`
/// and fails while `down` is set.
#[derive(Clone, Default)]
struct MockSink {
    stored: Arc<Mutex<BTreeMap<String, String>>>,
    down: Arc<AtomicBool>,
    delay: Duration,
}

impl WriteSink<String, IfcWrite> for MockSink {
    async fn apply_batch(&self, writes: &[(&String, &IfcWrite)]) -> Vec<Result<(), BackendError>> {
        tokio::time::sleep(self.delay).await;
        if self.down.load(Ordering::SeqCst) {
            return writes
                .iter()
                .map(|_| Err(BackendError::Connection("connection refused".to_string())))
                .collect();
        }
        let mut stored = self.stored.lock().expect("stored");
        for (aor, write) in writes {
            match write {
                IfcWrite::Save(xml) => {
                    stored.insert((*aor).clone(), xml.clone());
                }
                IfcWrite::Remove => {
                    stored.remove(*aor);
                }
            }
        }
        writes.iter().map(|_| Ok(())).collect()
    }
}

fn aor(index: usize) -> String {
    format!("sip:user{index}@example.com")
}

/// Wait (in paused time) until the sink holds exactly `expected`.
async fn converged(sink: &MockSink, expected: &BTreeMap<String, String>) {
    for _ in 0..600 {
        if *sink.stored.lock().expect("stored") == *expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stored = sink.stored.lock().expect("stored");
    panic!(
        "the sink never caught up: {} profiles held, {} expected",
        stored.len(),
        expected.len()
    );
}

/// A burst far past the old 4096-command queue, stores and removals mixed:
/// every profile lands and every removal takes, against a slow sink.
#[tokio::test(start_paused = true)]
async fn a_profile_burst_reaches_a_slow_sink_in_full() {
    const USERS: usize = 6_000;
    let sink = MockSink {
        delay: Duration::from_millis(5),
        ..MockSink::default()
    };
    let store = IfcStore::new(Vec::new());
    let writer = spawn_ifc_writer(sink.clone());
    store.set_backend_writer(writer.clone());

    for user in 0..USERS {
        store.store_profile_xml(&aor(user), PROFILE).expect("store");
    }
    for user in 0..USERS / 2 {
        store.remove_profile(&aor(user));
    }

    let expected: BTreeMap<String, String> = (USERS / 2..USERS)
        .map(|user| (aor(user), PROFILE.to_string()))
        .collect();
    converged(&sink, &expected).await;
}

/// A Redis outage holds the profile writes rather than losing them, and they
/// drain once Redis answers; the pending map is then empty (the per-module
/// leak gate).
#[tokio::test(start_paused = true)]
async fn profile_writes_during_an_outage_drain_once_redis_recovers() {
    let sink = MockSink {
        delay: Duration::from_millis(1),
        ..MockSink::default()
    };
    let store = IfcStore::new(Vec::new());
    let writer = spawn_ifc_writer(sink.clone());
    store.set_backend_writer(writer.clone());

    sink.down.store(true, Ordering::SeqCst);
    for user in 0..500 {
        store.store_profile_xml(&aor(user), PROFILE).expect("store");
    }
    for user in 0..100 {
        store.remove_profile(&aor(user));
    }
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(sink.stored.lock().expect("stored").is_empty());
    assert_eq!(writer.pending_writes(), 500);

    sink.down.store(false, Ordering::SeqCst);
    let expected: BTreeMap<String, String> = (100..500)
        .map(|user| (aor(user), PROFILE.to_string()))
        .collect();
    converged(&sink, &expected).await;
    for _ in 0..100 {
        if writer.pending_writes() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(writer.pending_writes(), 0);
}
