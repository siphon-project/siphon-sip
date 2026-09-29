//! Which SIP Call-IDs an engine call's end-of-call summary belongs to.
//!
//! A bridged pair relays through one engine call on a fresh id, stored under
//! the anchor's SIP Call-ID; the peer has no entry at all. The summary names
//! the engine id, so the store keeps who it covers while the session lives and
//! for a grace window after it is removed (the summary follows the delete).

use super::*;
use crate::control::CHANNEL_TOMBSTONE_GRACE;

fn session(call_id: &str, engine_call_id: &str) -> MediaSession {
    MediaSession {
        call_id: call_id.to_string(),
        rtpengine_call_id: engine_call_id.to_string(),
        from_tag: "tag-a".to_string(),
        to_tag: Some("tag-b".to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: Instant::now(),
    }
}

/// Record `sip_call_ids` as the parties of `engine_call_id`, with no tags:
/// what the summary needs, which is all these tests read.
fn record(store: &MediaSessionStore, call_id: &str, engine_call_id: &str, sip_call_ids: &[&str]) {
    let parties: Vec<(&str, Option<&str>)> = sip_call_ids.iter().map(|id| (*id, None)).collect();
    store.record_parties(call_id, engine_call_id, &parties);
}

/// A pair's per-party event goes to the party whose engine tag it names, and
/// only that one; a tag no party (or both) carries goes nowhere. Nothing is
/// spent: a call reports many.
#[tokio::test]
async fn a_per_party_event_goes_to_the_party_its_tag_names() {
    let store = MediaSessionStore::new();
    store.insert(session("event-anchor@example.test", "event-pair"));
    store.record_parties(
        "event-anchor@example.test",
        "event-pair",
        &[
            ("event-anchor@example.test", Some("tag-anchor")),
            ("event-peer@example.test", Some("tag-peer")),
        ],
    );
    assert_eq!(
        store.event_party("event-pair", "tag-peer").as_deref(),
        Some("event-peer@example.test")
    );
    assert_eq!(
        store.event_party("event-pair", "tag-anchor").as_deref(),
        Some("event-anchor@example.test")
    );
    assert_eq!(store.event_party("event-pair", "tag-stranger"), None);
    assert_eq!(store.engine_parties_count(), 1, "nothing spent");

    // One party: every event is its own, whatever the tag.
    store.insert(session("reanchor@example.test", "reanchor-engine"));
    assert_eq!(
        store.event_party("reanchor-engine", "any-tag").as_deref(),
        Some("reanchor@example.test")
    );
    // Nothing recorded: the engine id is the SIP Call-ID.
    assert_eq!(
        store.event_party("plain@example.test", "tag-a").as_deref(),
        Some("plain@example.test")
    );
}

/// Two parties on one tag cannot be told apart: neither gets the event.
#[tokio::test]
async fn a_tag_both_parties_carry_names_neither() {
    let store = MediaSessionStore::new();
    store.insert(session("same-anchor@example.test", "same-pair"));
    store.record_parties(
        "same-anchor@example.test",
        "same-pair",
        &[
            ("same-anchor@example.test", Some("shared-tag")),
            ("same-peer@example.test", Some("shared-tag")),
        ],
    );
    assert_eq!(store.event_party("same-pair", "shared-tag"), None);
}

/// The store key of the session on an engine call, whatever id the engine
/// knows it by; none once it has left the store.
#[tokio::test]
async fn an_engine_call_resolves_to_the_key_its_session_is_stored_under() {
    let store = MediaSessionStore::new();
    store.insert(session("key-plain@example.test", "key-plain@example.test"));
    store.insert(session("key-anchor@example.test", "key-pair"));
    record(
        &store,
        "key-anchor@example.test",
        "key-pair",
        &["key-anchor@example.test", "key-peer@example.test"],
    );
    assert_eq!(
        store
            .session_key_for_engine_call("key-plain@example.test")
            .as_deref(),
        Some("key-plain@example.test")
    );
    assert_eq!(
        store.session_key_for_engine_call("key-pair").as_deref(),
        Some("key-anchor@example.test")
    );
    assert_eq!(store.session_key_for_engine_call("key-unknown"), None);
    store.remove("key-anchor@example.test");
    assert_eq!(store.session_key_for_engine_call("key-pair"), None);
}

/// A session on its own SIP Call-ID needs nothing recorded: its summary
/// names the call it belongs to.
#[tokio::test]
async fn a_session_on_its_own_call_id_is_its_own_party() {
    let store = MediaSessionStore::new();
    store.insert(session("plain@example.test", "plain@example.test"));
    assert_eq!(store.engine_parties_count(), 0);
    assert_eq!(
        store.summary_parties("plain@example.test"),
        ["plain@example.test"]
    );
    store.remove("plain@example.test");
    assert_eq!(store.engine_parties_count(), 0);
}

/// A bridged pair's summary belongs to both parties, anchor first, whether it
/// arrives while the session lives or after it was removed; it is resolved
/// once.
#[tokio::test]
async fn a_bridged_pairs_summary_belongs_to_both_parties() {
    let store = MediaSessionStore::new();
    store.insert(session("anchor@example.test", "pair-fresh"));
    record(
        &store,
        "anchor@example.test",
        "pair-fresh",
        &["anchor@example.test", "peer@example.test"],
    );
    assert_eq!(
        store.summary_parties("pair-fresh"),
        ["anchor@example.test", "peer@example.test"]
    );
    assert_eq!(store.engine_parties_count(), 0, "spent on resolution");

    // After teardown: the summary follows the delete.
    store.insert(session("anchor2@example.test", "pair-fresh-2"));
    record(
        &store,
        "anchor2@example.test",
        "pair-fresh-2",
        &["anchor2@example.test", "peer2@example.test"],
    );
    store.remove("anchor2@example.test");
    assert_eq!(store.engine_parties_count(), 1, "kept for the late summary");
    assert_eq!(
        store.summary_parties("pair-fresh-2"),
        ["anchor2@example.test", "peer2@example.test"]
    );
    assert_eq!(store.engine_parties_count(), 0);
}

/// A pair renegotiated in place keeps the anchor's own engine id; the summary
/// still reaches the peer too, and never names a party twice.
#[tokio::test]
async fn an_in_place_pair_names_each_party_once() {
    let store = MediaSessionStore::new();
    store.insert(session("inplace@example.test", "inplace@example.test"));
    record(
        &store,
        "inplace@example.test",
        "inplace@example.test",
        &[
            "inplace@example.test",
            "inplace-peer@example.test",
            "inplace@example.test",
        ],
    );
    store.remove("inplace@example.test");
    assert_eq!(
        store.summary_parties("inplace@example.test"),
        ["inplace@example.test", "inplace-peer@example.test"]
    );
}

/// Parties are only recorded for the engine call the stored session is on:
/// a stale id, or a key with no session, records nothing to leak.
#[tokio::test]
async fn parties_are_recorded_only_for_the_stored_engine_call() {
    let store = MediaSessionStore::new();
    record(
        &store,
        "absent@example.test",
        "ghost",
        &["absent@example.test"],
    );
    store.insert(session("stored@example.test", "stored-engine"));
    record(
        &store,
        "stored@example.test",
        "other-engine",
        &["stored@example.test"],
    );
    assert_eq!(
        store.engine_parties_count(),
        1,
        "only the decoupled session itself"
    );
    assert_eq!(store.summary_parties("ghost"), ["ghost"]);
    assert_eq!(store.summary_parties("other-engine"), ["other-engine"]);
}

/// A session on an engine id of its own (a re-anchor) resolves to its SIP
/// Call-ID with nothing else recorded.
#[tokio::test]
async fn a_decoupled_session_resolves_to_its_call_id() {
    let store = MediaSessionStore::new();
    store.insert(session("reanchored@example.test", "reanchor-engine"));
    store.remove("reanchored@example.test");
    assert_eq!(
        store.summary_parties("reanchor-engine"),
        ["reanchored@example.test"]
    );
}

/// A session replaced under its key by one on another engine id (a bridge
/// adopting the anchor's entry, a re-bridge) keeps the replaced call's
/// parties for its own summary.
#[tokio::test]
async fn a_replaced_session_keeps_its_parties_for_its_summary() {
    let store = MediaSessionStore::new();
    store.insert(session("rebridged@example.test", "first-pair"));
    record(
        &store,
        "rebridged@example.test",
        "first-pair",
        &["rebridged@example.test", "first-peer@example.test"],
    );
    store.insert(session("rebridged@example.test", "second-pair"));
    assert_eq!(
        store.summary_parties("first-pair"),
        ["rebridged@example.test", "first-peer@example.test"]
    );
    assert_eq!(
        store.summary_parties("second-pair"),
        ["rebridged@example.test"]
    );
}

/// Past the grace window a removed session's parties are gone on their own;
/// a live session's are kept however long the call lasts.
#[tokio::test(start_paused = true)]
async fn removed_parties_expire_after_the_grace_window() {
    let store = MediaSessionStore::new();
    store.insert(session("live@example.test", "live-pair"));
    store.insert(session("ended@example.test", "ended-pair"));
    record(
        &store,
        "ended@example.test",
        "ended-pair",
        &["ended@example.test", "ended-peer@example.test"],
    );
    store.remove("ended@example.test");

    tokio::time::sleep(CHANNEL_TOMBSTONE_GRACE - std::time::Duration::from_secs(1)).await;
    assert_eq!(store.engine_parties_count(), 2, "both still held");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert_eq!(store.engine_parties_count(), 1, "the removed one expired");
    assert_eq!(store.summary_parties("ended-pair"), ["ended-pair"]);
    assert_eq!(
        store.summary_parties("live-pair"),
        ["live@example.test"],
        "the live one is kept"
    );
}

/// A stale-session sweep releases what it removes the way `remove` does.
#[tokio::test(start_paused = true)]
async fn a_swept_session_releases_its_parties() {
    let store = MediaSessionStore::new();
    let mut stale = session("stale@example.test", "stale-pair");
    stale.created_at = Instant::now() - std::time::Duration::from_secs(7200);
    store.insert(stale);
    store.sweep_stale(std::time::Duration::from_secs(3600));
    assert!(store.is_empty());
    assert_eq!(store.engine_parties_count(), 1);
    tokio::time::sleep(CHANNEL_TOMBSTONE_GRACE + std::time::Duration::from_secs(1)).await;
    assert_eq!(store.engine_parties_count(), 0);
}

/// Leak gate: after a batch of bridged pairs torn down, the parties map is
/// back at its baseline, half through their summary and half through expiry.
#[tokio::test(start_paused = true)]
async fn the_parties_map_drains_to_baseline() {
    const PAIRS: usize = 500;
    let store = MediaSessionStore::new();
    assert_eq!(store.engine_parties_count(), 0);
    for index in 0..PAIRS {
        let anchor = format!("leak-anchor-{index}@example.test");
        let peer = format!("leak-peer-{index}@example.test");
        let engine = format!("leak-pair-{index}");
        store.insert(session(&anchor, &engine));
        record(&store, &anchor, &engine, &[anchor.as_str(), peer.as_str()]);
    }
    assert_eq!(store.engine_parties_count(), PAIRS);
    for index in 0..PAIRS {
        store.remove(&format!("leak-anchor-{index}@example.test"));
    }
    assert!(store.is_empty());
    assert_eq!(store.engine_parties_count(), PAIRS);

    for index in (0..PAIRS).step_by(2) {
        assert_eq!(
            store.summary_parties(&format!("leak-pair-{index}")).len(),
            2
        );
    }
    assert_eq!(store.engine_parties_count(), PAIRS / 2);
    tokio::time::sleep(CHANNEL_TOMBSTONE_GRACE + std::time::Duration::from_secs(1)).await;
    assert_eq!(store.engine_parties_count(), 0);
}
