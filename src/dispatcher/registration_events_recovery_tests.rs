//! Recovery after a lag interleaves with live events instead of blocking them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, Notify};

use super::*;
use crate::metrics::event_lag::{snapshot_aors, snapshots};
use crate::sip::uri::SipUri;

fn save(registrar: &Registrar, user: &str) {
    registrar
        .save(
            &format!("sip:{user}@example.com"),
            SipUri::new("192.0.2.10".to_string()).with_user(user.to_string()),
            3600,
            1.0,
            format!("call-{user}"),
            1,
        )
        .expect("saved");
}

type Seen<T> = Arc<Mutex<Vec<T>>>;

fn snapshot_of(seen: &Seen<RegistrarChange>) -> Vec<String> {
    seen.lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .filter(|change| change.is_snapshot())
        .map(|change| change.aor.clone())
        .collect()
}

/// A sink that sleeps `pause` per delivery and parks delivery number `n`
/// until `gates[n]` is released.
fn paced_sink<T: Clone + Send + 'static>(
    seen: Seen<T>,
    pause: Duration,
    gates: HashMap<usize, Arc<Notify>>,
) -> impl FnMut(T) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
    let mut index = 0usize;
    move |change: T| {
        let seen = Arc::clone(&seen);
        let gate = gates.get(&index).cloned();
        index += 1;
        Box::pin(async move {
            if let Some(gate) = gate {
                gate.notified().await;
            }
            if !pause.is_zero() {
                tokio::time::sleep(pause).await;
            }
            seen.lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(change);
        })
    }
}

fn registered(aor: &str) -> RegistrationEvent {
    RegistrationEvent::Registered {
        aor: aor.to_string(),
        exchange: None,
    }
}

fn expired(aor: &str) -> RegistrationEvent {
    RegistrationEvent::Expired {
        aor: aor.to_string(),
    }
}

async fn wait_until(mut condition: impl FnMut() -> bool) {
    for _ in 0..3000 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the condition never held");
}

#[tokio::test]
async fn a_walk_longer_than_the_channel_holds_does_not_livelock_the_consumer() {
    const AORS: usize = 200;
    const LIVE: usize = 60;
    let registrar = Arc::new(Registrar::default());
    for index in 0..AORS {
        save(&registrar, &format!("held{index}"));
    }
    let (sender, receiver) = broadcast::channel(8);
    let seen: Seen<RegistrarChange> = Arc::default();
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrar_events(
        receiver,
        Arc::clone(&registrar),
        paced_sink(
            Arc::clone(&seen),
            Duration::from_millis(1),
            HashMap::from([(0, Arc::clone(&gate))]),
        ),
    ));

    // Park the consumer on its first event and overrun the channel.
    let _ = sender.send(registered("sip:first@example.com"));
    tokio::time::sleep(Duration::from_millis(30)).await;
    for index in 0..40 {
        let _ = sender.send(expired(&format!("sip:filler{index}@example.com")));
    }
    gate.notify_one();

    // A steady stream of live events at a rate the consumer can keep up with,
    // while the recovery runs.
    let producer = tokio::spawn({
        let sender = sender.clone();
        async move {
            for index in 0..LIVE {
                let _ = sender.send(registered(&format!("sip:live{index}@example.com")));
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(20), producer)
        .await
        .expect("the producer finishes")
        .expect("the producer did not panic");

    let all_reported = |seen: &Seen<RegistrarChange>| {
        let snapshot = snapshot_of(seen);
        (0..AORS).all(|index| snapshot.contains(&format!("sip:held{index}@example.com")))
    };
    tokio::time::timeout(Duration::from_secs(20), async {
        wait_until(|| all_reported(&seen)).await;
    })
    .await
    .expect("every held AoR is re-reported");

    let delivered = seen.lock().unwrap_or_else(|error| error.into_inner());
    let live: Vec<&str> = delivered
        .iter()
        .filter(|change| change.event == "registered" && change.aor.starts_with("sip:live"))
        .map(|change| change.aor.as_str())
        .collect();
    let expected: Vec<String> = (0..LIVE)
        .map(|index| format!("sip:live{index}@example.com"))
        .collect();
    assert_eq!(
        live, expected,
        "every live event published during the recovery is delivered, in order"
    );
    drop(delivered);
    let mut runs: HashMap<String, usize> = HashMap::new();
    for aor in snapshot_of(&seen) {
        *runs.entry(aor).or_default() += 1;
    }
    assert!(
        runs.values().all(|count| *count <= 2),
        "the snapshot does not restart for ever"
    );
    task.abort();
}

fn flood(sender: &broadcast::Sender<RegistrationEvent>, count: usize) {
    for index in 0..count {
        let _ = sender.send(expired(&format!("sip:filler{index}@example.com")));
    }
}

#[tokio::test]
async fn a_lag_during_a_pending_snapshot_replaces_it() {
    crate::metrics::init().expect("the metrics build");
    const AORS: usize = 20;
    let registrar = Arc::new(Registrar::default());
    for index in 0..AORS {
        save(&registrar, &format!("held{index}"));
    }
    let runs_before = snapshots(LaggedConsumer::Registrar);
    let aors_before = snapshot_aors(LaggedConsumer::Registrar);
    let (sender, receiver) = broadcast::channel(4);
    let seen: Seen<RegistrarChange> = Arc::default();
    let first = Arc::new(Notify::new());
    // Delivery 0 is the event that parks the consumer, 1..=4 the events the
    // channel still holds after the lag, 5 the first snapshot AoR.
    let during_snapshot = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrar_events(
        receiver,
        Arc::clone(&registrar),
        paced_sink(
            Arc::clone(&seen),
            Duration::ZERO,
            HashMap::from([(0, Arc::clone(&first)), (5, Arc::clone(&during_snapshot))]),
        ),
    ));

    let _ = sender.send(expired("sip:first@example.com"));
    tokio::time::sleep(Duration::from_millis(30)).await;
    flood(&sender, 10);
    first.notify_one();
    // The consumer is parked on the first snapshot AoR; lag it again.
    tokio::time::sleep(Duration::from_millis(100)).await;
    flood(&sender, 10);
    during_snapshot.notify_one();

    wait_until(|| snapshot_of(&seen).len() > AORS).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let snapshot = snapshot_of(&seen);
    assert_eq!(
        snapshot.len(),
        AORS + 1,
        "the AoR in flight, then one fresh run of every held AoR: the first run is not queued behind"
    );
    let mut per_aor: HashMap<&String, usize> = HashMap::new();
    for aor in &snapshot {
        *per_aor.entry(aor).or_default() += 1;
    }
    assert_eq!(per_aor.len(), AORS, "every held AoR is re-reported");
    assert!(per_aor.values().all(|count| *count <= 2));
    assert!(snapshots(LaggedConsumer::Registrar) >= runs_before + 2);
    assert!(snapshot_aors(LaggedConsumer::Registrar) > aors_before + (AORS as u64));
    task.abort();
}

#[tokio::test]
async fn a_deregistration_lost_in_the_lag_is_re_reported_as_a_snapshot_with_no_bindings() {
    let registrar = Arc::new(Registrar::default());
    save(&registrar, "keep");
    let (sender, receiver) = broadcast::channel(4);
    let seen: Seen<RegistrarChange> = Arc::default();
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrar_events(
        receiver,
        Arc::clone(&registrar),
        paced_sink(
            Arc::clone(&seen),
            Duration::ZERO,
            HashMap::from([(0, Arc::clone(&gate))]),
        ),
    ));

    // The consumer learns the AoR registered, then the lag swallows its
    // deregistration: it is not among the events the channel still holds.
    let _ = sender.send(registered("sip:gone@example.com"));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let _ = sender.send(RegistrationEvent::Deregistered {
        aor: "sip:gone@example.com".to_string(),
        exchange: None,
    });
    flood(&sender, 10);
    gate.notify_one();

    wait_until(|| {
        let snapshot = snapshot_of(&seen);
        snapshot.contains(&"sip:gone@example.com".to_string())
            && snapshot.contains(&"sip:keep@example.com".to_string())
    })
    .await;
    assert!(
        registrar.lookup("sip:gone@example.com").is_empty(),
        "the handler reading its state finds no bindings"
    );
    let delivered = seen.lock().unwrap_or_else(|error| error.into_inner());
    assert!(
        !delivered
            .iter()
            .any(|change| change.event == "deregistered" && change.aor.contains("gone")),
        "the deregistration itself was lost"
    );
    drop(delivered);
    task.abort();
}

#[tokio::test]
async fn a_registrant_recovery_delivers_live_events_first_and_recovers_removals() {
    let registrant = Arc::new(super::tests::registrant_manager());
    registrant.add(super::tests::registrant_entry("sip:trunk-a@example.net"));
    registrant.add(super::tests::registrant_entry("sip:trunk-b@example.net"));
    let runs_before = snapshots(LaggedConsumer::Registrant);
    let (sender, receiver) = broadcast::channel(4);
    let seen: Seen<RegistrantChange> = Arc::default();
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrant_events(
        receiver,
        Arc::clone(&registrant),
        paced_sink(
            Arc::clone(&seen),
            Duration::ZERO,
            HashMap::from([(0, Arc::clone(&gate))]),
        ),
    ));

    let _ = sender.send(RegistrantEvent::Registered {
        aor: "sip:trunk-gone@example.net".to_string(),
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    for index in 0..10 {
        let _ = sender.send(RegistrantEvent::Refreshed {
            aor: format!("sip:live{index}@example.net"),
        });
    }
    gate.notify_one();

    wait_until(|| {
        seen.lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .filter(|change| change.event == SNAPSHOT)
            .count()
            >= 3
    })
    .await;
    let delivered = seen.lock().unwrap_or_else(|error| error.into_inner());
    // The parked event, the four the channel still holds (live0..live5 were
    // lost), then only snapshots: live events go first.
    assert_eq!(delivered[0].aor, "sip:trunk-gone@example.net");
    let live: Vec<&str> = delivered[1..5]
        .iter()
        .map(|change| change.aor.as_str())
        .collect();
    assert_eq!(
        live,
        [
            "sip:live6@example.net",
            "sip:live7@example.net",
            "sip:live8@example.net",
            "sip:live9@example.net"
        ]
    );
    assert!(delivered[5..].iter().all(|change| change.event == SNAPSHOT));
    let snapshot: HashSet<&str> = delivered[5..]
        .iter()
        .map(|change| change.aor.as_str())
        .collect();
    // The lost registration is re-reported although it is no longer held, and
    // the entries added to the manager are re-told.
    assert!(snapshot.contains("sip:trunk-gone@example.net"));
    assert!(snapshot.contains("sip:trunk-a@example.net"));
    assert!(snapshot.contains("sip:trunk-b@example.net"));
    assert!(snapshots(LaggedConsumer::Registrant) > runs_before);
    drop(delivered);
    task.abort();
}

#[tokio::test]
async fn a_removal_of_an_aor_held_before_the_drain_started_is_recovered() {
    // Restored from a backend: held, but no event was ever published for it.
    let registrar = Arc::new(Registrar::default());
    save(&registrar, "restored");
    let (sender, receiver) = broadcast::channel(4);
    let seen: Seen<RegistrarChange> = Arc::default();
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrar_events(
        receiver,
        Arc::clone(&registrar),
        paced_sink(
            Arc::clone(&seen),
            Duration::ZERO,
            HashMap::from([(0, Arc::clone(&gate))]),
        ),
    ));
    let _ = sender.send(expired("sip:first@example.com"));
    tokio::time::sleep(Duration::from_millis(30)).await;
    // Its removal happens inside the lag and never reaches this channel.
    registrar.remove_all("sip:restored@example.com");
    flood(&sender, 10);
    gate.notify_one();

    wait_until(|| snapshot_of(&seen).contains(&"sip:restored@example.com".to_string())).await;
    assert!(registrar.lookup("sip:restored@example.com").is_empty());
    task.abort();
}

#[test]
fn the_remembered_set_drains_back_after_deregistrations() {
    let mut recovery = Recovery::default();
    for index in 0..1000 {
        recovery.track(&format!("sip:u{index}@example.com"), Presence::Present);
    }
    assert_eq!(recovery.known.len(), 1000);
    // A snapshot after every one of them went away reports them as gone and
    // forgets them as it does.
    let pending = recovery.begin_snapshot(HashSet::new());
    assert_eq!(pending, 1000);
    let mut reported = 0;
    while recovery.next_pending().is_some() {
        reported += 1;
    }
    assert_eq!(reported, 1000);
    assert!(recovery.known.is_empty(), "nothing is remembered for ever");
    assert!(recovery.pending.is_empty());
    assert!(recovery.queue.is_empty());

    // Live removals forget them too.
    for index in 0..1000 {
        recovery.track(&format!("sip:u{index}@example.com"), Presence::Present);
    }
    for index in 0..1000 {
        recovery.track(&format!("sip:u{index}@example.com"), Presence::Absent);
    }
    assert!(recovery.known.is_empty());
}

#[test]
fn a_live_event_takes_its_aor_out_of_the_pending_snapshot() {
    let mut recovery = Recovery::default();
    let held: HashSet<String> = ["sip:a@example.com", "sip:b@example.com"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(recovery.begin_snapshot(held), 2);
    recovery.track("sip:a@example.com", Presence::Present);
    assert_eq!(
        recovery.next_pending().as_deref(),
        Some("sip:b@example.com")
    );
    assert_eq!(recovery.next_pending(), None);
    // A second lag replaces rather than appends.
    let held: HashSet<String> = ["sip:c@example.com"]
        .into_iter()
        .map(String::from)
        .collect();
    let first = recovery.begin_snapshot(held.clone());
    let second = recovery.begin_snapshot(held);
    // The new AoR plus the two remembered ones that are not held.
    assert_eq!((first, second), (3, 3));
    assert_eq!(recovery.queue.len(), 3);
}
