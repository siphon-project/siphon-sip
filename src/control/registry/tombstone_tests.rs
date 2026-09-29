//! A channel's tombstone: after `StasisEnd` removed it, the media engine's
//! end-of-call `MediaSummary` still reaches the connection that owned it, for
//! [`CHANNEL_TOMBSTONE_GRACE`], and to nobody else.

use super::*;
use crate::control::protocol::EventFrame;

fn app(name: &str) -> ControlAppConfig {
    ControlAppConfig {
        name: name.to_string(),
        token: format!("token-{name}"),
        per_call_connect: false,
        connect_url: None,
        on_lost: Some("hangup".to_string()),
        ca_file: None,
        events: Vec::new(),
    }
}

fn bus() -> Arc<ControlBus> {
    let (command_tx, _commands) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![app("ivr-app"), app("other-app")],
        64,
        SlowConsumerPolicy::DropOldest,
        10,
        3000,
    )
}

fn summary() -> serde_json::Value {
    serde_json::json!({ "reason": "delete", "duration_ms": 42000, "legs": [] })
}

/// Every event frame queued for `conn` so far, in order. Closes the queue, so
/// call it once per connection, at the end.
async fn queued_events(conn: &Arc<ConnHandle>) -> Vec<EventFrame> {
    conn.events.close();
    conn.events
        .recv_many()
        .await
        .into_iter()
        .filter_map(|frame| match frame {
            OutboundFrame::Event(event) => Some(event),
            OutboundFrame::Reply(_) => None,
        })
        .collect()
}

fn controlled(bus: &Arc<ControlBus>, conn: &Arc<ConnHandle>, channel: &str, sip_call_id: &str) {
    bus.register_channel(
        channel,
        conn,
        &format!("actor-{channel}"),
        sip_call_id,
        "hangup",
        HashMap::new(),
    );
}

/// An ordinary hang-up: `StasisEnd` goes out and the channel is removed, then
/// the engine's summary arrives and reaches the owner, carrying the channel id
/// the call had. The tombstone is spent on delivery.
#[tokio::test]
async fn a_hang_up_delivers_the_summary_to_the_owner_after_stasis_end() {
    let bus = bus();
    let owner = bus.register_connection("ivr-app");
    controlled(&bus, &owner, "ch-hangup", "hangup@example.test");

    bus.on_call_terminated("hangup@example.test", "bye");
    assert_eq!(bus.channel_count(), 0, "StasisEnd removed the channel");
    assert_eq!(bus.channel_tombstone_count(), 1);

    assert!(bus.forward_media_summary("hangup@example.test", summary()));
    assert_eq!(bus.channel_tombstone_count(), 0, "spent on delivery");
    assert!(
        !bus.forward_media_summary("hangup@example.test", summary()),
        "a second summary finds nothing"
    );

    let events = queued_events(&owner).await;
    let names: Vec<&str> = events.iter().map(|event| event.event.as_str()).collect();
    assert_eq!(names, ["StasisEnd", "MediaSummary"]);
    let summary_event = &events[1];
    assert_eq!(summary_event.channel.as_deref(), Some("ch-hangup"));
    assert_eq!(summary_event.call_id.as_deref(), Some("actor-ch-hangup"));
    assert_eq!(
        summary_event.sip_call_id.as_deref(),
        Some("hangup@example.test")
    );
    assert_eq!(summary_event.payload["duration_ms"], 42000);
}

/// The summary goes to the owning connection and nowhere else: not another
/// app, not another connection of the same app, and a summary for a call
/// nobody controlled reaches no one.
#[tokio::test]
async fn a_summary_after_stasis_end_reaches_only_its_owner() {
    let bus = bus();
    let owner = bus.register_connection("ivr-app");
    let sibling = bus.register_connection("ivr-app");
    let other = bus.register_connection("other-app");
    controlled(&bus, &owner, "ch-owned", "owned@example.test");

    bus.on_call_terminated("owned@example.test", "bye");
    assert!(!bus.forward_media_summary("nobody@example.test", summary()));
    assert!(bus.forward_media_summary("owned@example.test", summary()));

    let owner_events = queued_events(&owner).await;
    assert!(owner_events
        .iter()
        .any(|event| event.event == "MediaSummary"));
    assert!(queued_events(&sibling).await.is_empty());
    assert!(queued_events(&other).await.is_empty());
}

/// Past the grace window the tombstone is gone on its own, and a summary that
/// late is dropped rather than delivered.
#[tokio::test(start_paused = true)]
async fn a_tombstone_expires_after_the_grace_window() {
    let bus = bus();
    let owner = bus.register_connection("ivr-app");
    controlled(&bus, &owner, "ch-late", "late@example.test");

    bus.on_call_terminated("late@example.test", "bye");
    assert_eq!(bus.channel_tombstone_count(), 1);
    tokio::time::sleep(CHANNEL_TOMBSTONE_GRACE - std::time::Duration::from_secs(1)).await;
    assert_eq!(
        bus.channel_tombstone_count(),
        1,
        "positive control: still held inside the window"
    );
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(bus.channel_tombstone_count(), 0, "expired");

    assert!(!bus.forward_media_summary("late@example.test", summary()));
    let names: Vec<String> = queued_events(&owner)
        .await
        .into_iter()
        .map(|event| event.event)
        .collect();
    assert_eq!(names, ["StasisEnd"]);
}

/// A tombstone never outlives its owner's connection: once the owner has
/// disconnected, the summary is dropped.
#[tokio::test]
async fn a_tombstone_goes_with_its_owners_connection() {
    let bus = bus();
    let owner = bus.register_connection("ivr-app");
    let survivor = bus.register_connection("ivr-app");
    controlled(&bus, &owner, "ch-gone", "gone@example.test");
    controlled(&bus, &survivor, "ch-kept", "kept@example.test");

    bus.on_call_terminated("gone@example.test", "bye");
    bus.on_call_terminated("kept@example.test", "bye");
    assert_eq!(bus.channel_tombstone_count(), 2);

    bus.unregister_connection(&owner);
    assert_eq!(
        bus.channel_tombstone_count(),
        1,
        "only the disconnected owner's tombstone goes"
    );
    assert!(!bus.forward_media_summary("gone@example.test", summary()));
    assert!(bus.forward_media_summary("kept@example.test", summary()));
    assert!(queued_events(&survivor)
        .await
        .iter()
        .any(|event| event.event == "MediaSummary"));
}

/// A channel with no live owner at teardown (orphaned, waiting on its grace
/// timer) leaves no tombstone: there is nobody to deliver to.
#[tokio::test]
async fn an_orphaned_channel_leaves_no_tombstone() {
    let bus = bus();
    let owner = bus.register_connection("ivr-app");
    controlled(&bus, &owner, "ch-orphan", "orphan@example.test");
    bus.unregister_connection(&owner);

    bus.on_call_terminated("orphan@example.test", "bye");
    assert_eq!(bus.channel_tombstone_count(), 0);
}

/// Leak gate: the tombstone map returns to its baseline after a batch of
/// hang-ups, both through delivery and through expiry.
#[tokio::test(start_paused = true)]
async fn the_tombstone_map_drains_to_baseline() {
    const CALLS: usize = 500;
    let bus = bus();
    let owner = bus.register_connection("ivr-app");
    let baseline = bus.channel_tombstone_count();
    assert_eq!(baseline, 0);

    for index in 0..CALLS {
        let sip_call_id = format!("leak-{index}@example.test");
        controlled(&bus, &owner, &format!("ch-leak-{index}"), &sip_call_id);
        bus.on_call_terminated(&sip_call_id, "bye");
    }
    assert_eq!(bus.channel_count(), 0);
    assert_eq!(bus.channel_tombstone_count(), CALLS);

    // Half are claimed by their summary.
    for index in (0..CALLS).step_by(2) {
        assert!(bus.forward_media_summary(&format!("leak-{index}@example.test"), summary()));
    }
    assert_eq!(bus.channel_tombstone_count(), CALLS / 2);

    // The rest never get one and expire.
    tokio::time::sleep(CHANNEL_TOMBSTONE_GRACE + std::time::Duration::from_secs(1)).await;
    assert_eq!(bus.channel_tombstone_count(), baseline);
}
