//! The conference roster and `@b2bua.on_conference_change`, and
//! `b2bua.adopt_replaced(on_last_leave="end_owner")`, driven through the
//! dispatcher with the in-process native engine.
//!
//! The conference dialog is a call siphon answered and anchored itself, seated
//! in its room as a focus seats it (`conference_join`). The calls merged into
//! the room are bridged pairs the subscriber and a carrier are on. The
//! script's handlers write what they are told into lists of the `builtins`
//! module, one list per test, which the test reads back: the roster is the
//! process's, so a room is named per test and every read is by room.

use std::sync::Arc;

use super::adopt_replaced_tests::{
    conference_dialog, far_request, focus_running, merge, request_in, subscriber_called_out, Held,
    SUBSCRIBER,
};
use super::dial_bridge_test_harness::{caller_invite, caller_sends, eventually, Caller};
use super::dialog_state_events_tests::header;
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::TestDispatcher;
use super::*;
use crate::rtpengine::backend::{ConferenceRole, ConferenceSeat};
use crate::rtpengine::conference_roster::{self, SeatKind};
use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// What a handler was told: room, owner, change, seat, and the roster after it
/// as `(call_id, kind)`.
type Told = (
    String,
    Option<String>,
    String,
    String,
    Vec<(String, String)>,
);

fn script(list: &str, asynchronous: bool) -> String {
    format!(
        concat!(
            "import builtins\n",
            "from siphon import b2bua\n",
            "builtins.{list} = []\n",
            "builtins.{list}_bye = []\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    pass\n",
            "\n",
            "@b2bua.on_refer\n",
            "def on_refer(call):\n",
            "    pass\n",
            "\n",
            "@b2bua.on_bye\n",
            "def on_bye(call, initiator):\n",
            "    builtins.{list}_bye.append(call.conference)\n",
            "\n",
            "@b2bua.on_conference_change\n",
            "{asynchronous}def changed(conference_id, owner_call_id, change, call_id, roster):\n",
            "    builtins.{list}.append((conference_id, owner_call_id, change, call_id,\n",
            "                            [(seat['call_id'], seat['kind']) for seat in roster]))\n",
        ),
        list = list,
        asynchronous = if asynchronous { "async " } else { "" },
    )
}

fn told(list: &str, room: &str) -> Vec<Told> {
    pyo3::Python::attach(|python| {
        let all: Vec<Told> = python
            .import("builtins")
            .expect("builtins")
            .getattr(list)
            .expect("the script's list")
            .extract()
            .expect("tuples");
        all.into_iter().filter(|event| event.0 == room).collect()
    })
}

fn bye_conferences(list: &str) -> Vec<Option<(String, Option<String>)>> {
    pyo3::Python::attach(|python| {
        python
            .import("builtins")
            .expect("builtins")
            .getattr(format!("{list}_bye"))
            .expect("the script's list")
            .extract()
            .expect("tuples")
    })
}

/// A focus running `source`, with its roster events followed.
fn running(engine: &NativeTestEngine, source: &str) -> Arc<TestDispatcher> {
    let dispatcher = Arc::new(focus_running(engine, source));
    spawn_conference_change_events(Arc::clone(&dispatcher) as Arc<dyn DispatcherHandle>);
    dispatcher
}

/// The conference dialog, seated in `room` as the focus seats it.
async fn owner(
    dispatcher: &TestDispatcher,
    engine: &NativeTestEngine,
    room: &str,
    call_id: &str,
) -> Caller {
    let conference = conference_dialog(dispatcher, call_id, SUBSCRIBER);
    engine
        .backend()
        .conference_join_party(
            &conference.call_id,
            ConferenceSeat {
                conference_id: room.to_string(),
                from_tag: "caller-tag".to_string(),
            },
            "v=0\r\n",
            ConferenceRole::Talker,
            &NgFlags::default(),
            Some("sip:15550100001@example.com".to_string()),
        )
        .await
        .expect("the conference dialog is seated");
    conference
}

async fn adopt(
    dispatcher: &TestDispatcher,
    conference: &Caller,
    room: &str,
    held: &Held,
    end_owner: bool,
) {
    let mut request = request_in(room, conference, held.replaces_caller(), true);
    request.ends_owner_on_last = end_owner;
    let (status, _) = merge(dispatcher, conference, request).await;
    assert_eq!(status, 200);
}

fn carrier_hangs_up(dispatcher: &TestDispatcher, held: &Held) {
    let (inbound, message) = far_request(
        "BYE",
        2,
        &held.callee,
        &held.b_call_id,
        &held.b_local_tag,
        None,
    );
    tokio::task::block_in_place(|| handle_b2bua_bye(inbound, message, &dispatcher.state));
}

fn byes_to_the_conference_dialog(sent: &[Sent], conference: &Caller) -> Vec<String> {
    sent.iter()
        .filter(|frame| frame.destination == socket(SUBSCRIBER) && frame.is(Method::Bye))
        .filter(|frame| header(&frame.message, "Call-ID") == conference.call_id)
        .map(|frame| header(&frame.message, "Reason"))
        .collect()
}

fn call_ids(roster: &[(String, String)]) -> Vec<&str> {
    roster.iter().map(|(call_id, _)| call_id.as_str()).collect()
}

/// An owner and two adopted calls: when both far parties hang up, the owner is
/// ended with Q.850 cause 16 through the normal teardown, and its own seat
/// leaves. Each step is told exactly once.
#[tokio::test(flavor = "multi_thread")]
async fn the_last_adopted_call_leaving_ends_the_owner() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_END_OWNER";
    let room = "roster-end-owner";
    let dispatcher = running(&engine, &script(list, false));
    let state = &dispatcher.state;
    let conference = owner(&dispatcher, &engine, room, "roster-end-owner@192.0.2.10").await;
    let first = subscriber_called_out(&dispatcher, &engine, "end-owner-1", SUBSCRIBER);
    let second = subscriber_called_out(&dispatcher, &engine, "end-owner-2", SUBSCRIBER);
    adopt(&dispatcher, &conference, room, &first, true).await;
    adopt(&dispatcher, &conference, room, &second, true).await;
    assert_eq!(conference_roster::roster(room).len(), 3);

    carrier_hangs_up(&dispatcher, &first);
    assert!(
        eventually(|| told(list, room).len() == 4).await,
        "{:?}",
        told(list, room)
    );
    let sent = drain(&dispatcher.udp);
    assert!(
        byes_to_the_conference_dialog(&sent, &conference).is_empty(),
        "the second call is still in the room: {sent:?}"
    );
    assert!(state
        .call_actors
        .get_call(&conference.internal_call_id)
        .is_some());

    carrier_hangs_up(&dispatcher, &second);
    assert!(
        eventually(|| told(list, room).len() == 6).await,
        "{:?}",
        told(list, room)
    );
    assert!(
        eventually(|| state
            .call_actors
            .get_call(&conference.internal_call_id)
            .is_none())
        .await,
        "the conference dialog is ended"
    );
    let sent = drain(&dispatcher.udp);
    let reasons = byes_to_the_conference_dialog(&sent, &conference);
    assert_eq!(reasons.len(), 1, "one BYE to the owner: {sent:?}");
    assert!(reasons[0].starts_with("Q.850;cause=16"), "{reasons:?}");

    let owner_id = conference.call_id.as_str();
    let events = told(list, room);
    let summary: Vec<(&str, &str, Vec<&str>)> = events
        .iter()
        .map(|event| {
            (
                event.2.as_str(),
                event.3.as_str(),
                call_ids(&event.4).into_iter().collect(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("joined", owner_id, vec![owner_id]),
            (
                "joined",
                first.b_call_id.as_str(),
                vec![owner_id, first.b_call_id.as_str()]
            ),
            (
                "joined",
                second.b_call_id.as_str(),
                vec![
                    owner_id,
                    first.b_call_id.as_str(),
                    second.b_call_id.as_str()
                ]
            ),
            (
                "left",
                first.b_call_id.as_str(),
                vec![owner_id, second.b_call_id.as_str()]
            ),
            ("left", second.b_call_id.as_str(), vec![owner_id]),
            ("left", owner_id, vec![]),
        ]
    );
    assert_eq!(events[1].1.as_deref(), Some(owner_id));
    assert_eq!(events[3].1.as_deref(), Some(owner_id));
    assert!(conference_roster::roster(room).is_empty());
    assert_eq!(
        crate::rtpengine::MediaBackend::conference_seat(owner_id),
        None
    );
    assert_eq!(state.call_actors.adoptions_len(), (0, 0));
}

/// The default leaves the room, and the conference dialog, as they are.
#[tokio::test(flavor = "multi_thread")]
async fn by_default_the_owner_stays_when_the_room_empties() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_KEEP_OWNER";
    let room = "roster-keep-owner";
    let dispatcher = running(&engine, &script(list, false));
    let state = &dispatcher.state;
    let conference = owner(&dispatcher, &engine, room, "roster-keep-owner@192.0.2.10").await;
    let first = subscriber_called_out(&dispatcher, &engine, "keep-owner-1", SUBSCRIBER);
    let second = subscriber_called_out(&dispatcher, &engine, "keep-owner-2", SUBSCRIBER);
    adopt(&dispatcher, &conference, room, &first, false).await;
    adopt(&dispatcher, &conference, room, &second, false).await;
    carrier_hangs_up(&dispatcher, &first);
    carrier_hangs_up(&dispatcher, &second);
    assert!(
        eventually(|| told(list, room).len() == 5).await,
        "{:?}",
        told(list, room)
    );
    // Nothing else is coming: give an end-owner that wrongly fires time to.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let sent = drain(&dispatcher.udp);
    assert!(byes_to_the_conference_dialog(&sent, &conference).is_empty());
    assert!(state
        .call_actors
        .get_call(&conference.internal_call_id)
        .is_some());
    let remaining = conference_roster::roster(room);
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].call_id, conference.call_id);
    assert_eq!(told(list, room).len(), 5);
}

/// Another seat in the room keeps the owner, whatever the policy.
#[tokio::test(flavor = "multi_thread")]
async fn a_seat_besides_the_owners_keeps_the_conference_dialog() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_OTHER_SEAT";
    let room = "roster-other-seat";
    let dispatcher = running(&engine, &script(list, false));
    let state = &dispatcher.state;
    let conference = owner(&dispatcher, &engine, room, "roster-other-seat@192.0.2.10").await;
    let held = subscriber_called_out(&dispatcher, &engine, "other-seat", SUBSCRIBER);
    adopt(&dispatcher, &conference, room, &held, true).await;
    // A participant dials in.
    engine
        .backend()
        .conference_join_party(
            "dialled-in@192.0.2.50",
            ConferenceSeat {
                conference_id: room.to_string(),
                from_tag: "dialled".to_string(),
            },
            "v=0\r\n",
            ConferenceRole::Listener,
            &NgFlags::default(),
            Some("sip:15550100077@example.com".to_string()),
        )
        .await
        .expect("seated");
    carrier_hangs_up(&dispatcher, &held);
    assert!(eventually(|| told(list, room).len() == 4).await);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(byes_to_the_conference_dialog(&drain(&dispatcher.udp), &conference).is_empty());
    assert!(state
        .call_actors
        .get_call(&conference.internal_call_id)
        .is_some());
    let events = told(list, room);
    // The dialled-in seat takes the owner the adopted seat agreed on.
    assert_eq!(events[2].2, "joined");
    assert_eq!(events[2].1.as_deref(), Some(conference.call_id.as_str()));
    // Tidy the process-wide seat.
    let seat = crate::rtpengine::MediaBackend::conference_seat("dialled-in@192.0.2.50")
        .expect("still seated");
    engine
        .backend()
        .conference_leave("dialled-in@192.0.2.50", &seat)
        .await
        .expect("left");
    let conference_seat =
        crate::rtpengine::MediaBackend::conference_seat(&conference.call_id).expect("seated");
    engine
        .backend()
        .conference_leave(&conference.call_id, &conference_seat)
        .await
        .expect("left");
}

/// A join and an adopt differ in kind, owner and party.
#[tokio::test(flavor = "multi_thread")]
async fn the_roster_tells_joined_seats_from_adopted_ones() {
    let engine = NativeTestEngine::start().await;
    let room = "roster-contents";
    let dispatcher = running(&engine, &script("ROSTER_CONTENTS", false));
    let conference = owner(&dispatcher, &engine, room, "roster-contents@192.0.2.10").await;
    let held = subscriber_called_out(&dispatcher, &engine, "contents", SUBSCRIBER);
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs_f64();
    adopt(&dispatcher, &conference, room, &held, false).await;

    let seats = conference_roster::roster(room);
    assert_eq!(seats.len(), 2);
    let (joined, adopted) = (&seats[0], &seats[1]);
    assert_eq!(joined.kind, SeatKind::Joined);
    assert_eq!(joined.call_id, conference.call_id);
    assert_eq!(joined.from_tag, "caller-tag");
    assert_eq!(
        joined.party_uri.as_deref(),
        Some("sip:15550100001@example.com")
    );
    assert_eq!(joined.role, "talker");
    assert_eq!(joined.owner_call_id, None);
    assert_eq!(adopted.kind, SeatKind::Adopted);
    assert_eq!(adopted.call_id, held.b_call_id);
    assert_eq!(
        adopted.party_uri.as_deref(),
        Some("sip:15550100042@carrier.example.com")
    );
    assert_eq!(adopted.role, "talker");
    assert_eq!(
        adopted.owner_call_id.as_deref(),
        Some(conference.call_id.as_str())
    );
    assert!(adopted.joined_at >= before - 1.0 && adopted.joined_at < before + 60.0);

    // The same through the script namespace.
    pyo3::Python::attach(|python| {
        let control = crate::script::api::b2bua::PyB2buaControl::new();
        let list = control.conference_roster(python, room).expect("the roster");
        let list = list.bind(python);
        assert_eq!(list.len().expect("a list"), 2);
        let adopted = list.get_item(1).expect("the adopted seat");
        let get = |key: &str| adopted.get_item(key).expect(key).to_string();
        assert_eq!(get("kind"), "adopted");
        assert_eq!(get("owner_call_id"), conference.call_id);
        assert_eq!(get("call_id"), held.b_call_id);
        let none = control
            .conference_roster(python, "roster-no-such-room")
            .expect("empty");
        assert_eq!(none.bind(python).len().expect("a list"), 0);
    });

    caller_sends(&dispatcher.state, &conference, "BYE", "3 BYE");
    // The teardown's media delete frees the conference dialog's seat.
    assert!(eventually(|| conference_roster::roster(room).is_empty()).await);
}

/// A reload between the events changes nothing: the room and the owner link
/// survive, and the reloaded handler is told the next one.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_reload_between_events_changes_nothing() {
    let engine = NativeTestEngine::start().await;
    let room = "roster-reload";
    let dispatcher = running(&engine, &script("ROSTER_BEFORE", false));
    let state = &dispatcher.state;
    let conference = owner(&dispatcher, &engine, room, "roster-reload@192.0.2.10").await;
    let first = subscriber_called_out(&dispatcher, &engine, "reload-1", SUBSCRIBER);
    let second = subscriber_called_out(&dispatcher, &engine, "reload-2", SUBSCRIBER);
    adopt(&dispatcher, &conference, room, &first, true).await;
    assert!(eventually(|| told("ROSTER_BEFORE", room).len() == 2).await);
    let roster_before = conference_roster::roster(room);

    // The deploy: a new script, its module state empty.
    let reloaded = crate::script::engine::ScriptEngine::new_embedded(&script("ROSTER_AFTER", true))
        .expect("the new script compiles");
    state
        .engine
        .state_arc()
        .store(reloaded.state_arc().load_full());
    assert_eq!(conference_roster::roster(room), roster_before);

    adopt(&dispatcher, &conference, room, &second, true).await;
    carrier_hangs_up(&dispatcher, &first);
    carrier_hangs_up(&dispatcher, &second);
    assert!(
        eventually(|| told("ROSTER_AFTER", room).len() == 4).await,
        "{:?}",
        told("ROSTER_AFTER", room)
    );
    assert_eq!(
        told("ROSTER_BEFORE", room).len(),
        2,
        "the old handler is gone"
    );
    let after = told("ROSTER_AFTER", room);
    assert_eq!(after[0].2, "joined");
    assert_eq!(after[0].3, second.b_call_id);
    assert_eq!(after[0].1.as_deref(), Some(conference.call_id.as_str()));
    assert_eq!(after[3].2, "left");
    // The owner link held across the reload: the owner was ended.
    assert!(
        eventually(|| state
            .call_actors
            .get_call(&conference.internal_call_id)
            .is_none())
        .await
    );
    let reasons = byes_to_the_conference_dialog(&drain(&dispatcher.udp), &conference);
    assert_eq!(reasons.len(), 1);
    assert!(reasons[0].starts_with("Q.850;cause=16"));
}

/// `call.conference` is there in `@b2bua.on_bye`, for an adopted call and for
/// the conference dialog.
#[tokio::test(flavor = "multi_thread")]
async fn call_conference_is_readable_in_on_bye() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_ON_BYE";
    let room = "roster-on-bye";
    let dispatcher = running(&engine, &script(list, false));
    let conference = owner(&dispatcher, &engine, room, "roster-on-bye@192.0.2.10").await;
    let held = subscriber_called_out(&dispatcher, &engine, "on-bye", SUBSCRIBER);
    // What the INVITE path keeps for the hooks to build the script's `Call` from.
    dispatcher.state.call_actors.set_a_leg_invite(
        &held.internal_call_id,
        Arc::new(std::sync::Mutex::new(caller_invite(
            &held.a_call_id,
            SUBSCRIBER,
        ))),
    );
    adopt(&dispatcher, &conference, room, &held, false).await;

    carrier_hangs_up(&dispatcher, &held);
    assert_eq!(
        bye_conferences(list),
        vec![Some((room.to_string(), Some(conference.call_id.clone())))]
    );
    caller_sends(&dispatcher.state, &conference, "BYE", "3 BYE");
    assert_eq!(
        bye_conferences(list),
        vec![
            Some((room.to_string(), Some(conference.call_id.clone()))),
            Some((room.to_string(), None)),
        ]
    );
    assert!(eventually(|| conference_roster::roster(room).is_empty()).await);
}

/// An `async` handler is told the same.
#[tokio::test(flavor = "multi_thread")]
async fn an_async_handler_is_told_too() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_ASYNC";
    let room = "roster-async";
    let dispatcher = running(&engine, &script(list, true));
    let conference = owner(&dispatcher, &engine, room, "roster-async@192.0.2.10").await;
    assert!(eventually(|| told(list, room).len() == 1).await);
    let conference_seat =
        crate::rtpengine::MediaBackend::conference_seat(&conference.call_id).expect("seated");
    engine
        .backend()
        .conference_leave(&conference.call_id, &conference_seat)
        .await
        .expect("left");
    assert!(eventually(|| told(list, room).len() == 2).await);
    assert_eq!(told(list, room)[1].2, "left");
}

/// A handler that raises does not stop the next change being told.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_raises_does_not_stop_the_next_change() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_RAISES";
    let room = "roster-raises";
    let source = script(list, false).replace(
        "    builtins.ROSTER_RAISES.append((conference_id",
        "    if change == 'joined':\n        builtins.ROSTER_RAISES.append((conference_id, 'raised', change, call_id, []))\n        raise RuntimeError('a script bug')\n    builtins.ROSTER_RAISES.append((conference_id",
    );
    let dispatcher = running(&engine, &source);
    let conference = owner(&dispatcher, &engine, room, "roster-raises@192.0.2.10").await;
    let conference_seat =
        crate::rtpengine::MediaBackend::conference_seat(&conference.call_id).expect("seated");
    engine
        .backend()
        .conference_leave(&conference.call_id, &conference_seat)
        .await
        .expect("left");
    assert!(eventually(|| told(list, room).len() == 2).await);
}

/// Every store the feature keeps drains to where it started after many whole
/// conferences, ended each way.
#[tokio::test(flavor = "multi_thread")]
async fn the_roster_and_the_owner_link_drain_to_baseline() {
    let engine = NativeTestEngine::start().await;
    let list = "ROSTER_LEAK";
    let dispatcher = running(&engine, &script(list, false));
    let state = &dispatcher.state;
    let calls_before = state.call_actors.count();
    let held_before = engine.held_count();
    let mut rooms = Vec::new();

    for round in 0..10 {
        let room = format!("roster-leak-dispatch-{round}");
        let conference = owner(
            &dispatcher,
            &engine,
            &room,
            &format!("roster-leak-dispatch-{round}@192.0.2.10"),
        )
        .await;
        let first = subscriber_called_out(
            &dispatcher,
            &engine,
            &format!("leak-d-{round}-1"),
            SUBSCRIBER,
        );
        let second = subscriber_called_out(
            &dispatcher,
            &engine,
            &format!("leak-d-{round}-2"),
            SUBSCRIBER,
        );
        adopt(&dispatcher, &conference, &room, &first, round % 2 == 0).await;
        adopt(&dispatcher, &conference, &room, &second, round % 2 == 0).await;
        if round % 3 == 0 {
            // The owner ends first, taking the calls it adopted with it.
            caller_sends(state, &conference, "BYE", "3 BYE");
        } else {
            carrier_hangs_up(&dispatcher, &first);
            carrier_hangs_up(&dispatcher, &second);
            if round % 2 == 1 {
                // Kept: the script ends the owner.
                caller_sends(state, &conference, "BYE", "3 BYE");
            }
        }
        if round % 3 != 0 && round % 2 == 0 {
            // The last call leaving ends the owner, on a task of its own: its
            // BYE is on the wire before this round's frames are read.
            assert!(
                eventually(|| state
                    .call_actors
                    .get_call(&conference.internal_call_id)
                    .is_none())
                .await
            );
        }
        drain(&dispatcher.udp);
        rooms.push(room);
    }
    assert!(
        eventually(|| rooms
            .iter()
            .all(|room| conference_roster::roster(room).is_empty()))
        .await,
        "every room is empty"
    );
    assert!(eventually(|| state.call_actors.count() == calls_before).await);
    assert!(eventually(|| engine.held_count() == held_before).await);
    assert_eq!(state.call_actors.adoptions_len(), (0, 0));
    // Each room was told one join and one leave per seat, owner included.
    for room in &rooms {
        assert!(
            eventually(|| told(list, room).len() == 6).await,
            "{room}: {:?}",
            told(list, room)
        );
    }
}
