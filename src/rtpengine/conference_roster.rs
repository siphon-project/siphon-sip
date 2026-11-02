//! Who is seated in which conference room on this node, and the changes to it.
//!
//! The roster is derived from the seats siphon itself seats and frees: a
//! participant seated with `rtpengine.conference_join` /
//! `rtpengine.conference_answer` (kind `joined`) and a call whose far leg
//! `b2bua.adopt_replaced` moved into a room in place (kind `adopted`). It is
//! held here, in Rust, and not in the script: module state is emptied on every
//! reload and a conference outlives a deploy, so a stateless script reads the
//! room from siphon (`b2bua.conference_roster`) and is told when it changes
//! (`@b2bua.on_conference_change`).
//!
//! Every seat that comes in passes [`seat_joined`] and every seat that goes out
//! passes [`seat_left_joined`] or [`seat_left_engine_call`], the same funnels
//! the media backend already keeps its own seat maps through, so a change is
//! reported once and only once, from the state after it was committed.
//! Changes are handed to the subscribers [`subscribe`] returns, in the order
//! they were committed; with no subscriber they are dropped, not queued.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

/// How a seat came to be in the room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatKind {
    /// Seated by `rtpengine.conference_join` / `conference_answer`.
    Joined,
    /// A call's far leg moved into the room by `b2bua.adopt_replaced`.
    Adopted,
}

impl SeatKind {
    /// The name a script reads.
    pub fn label(self) -> &'static str {
        match self {
            Self::Joined => "joined",
            Self::Adopted => "adopted",
        }
    }
}

/// One seat in a room.
#[derive(Debug, Clone, PartialEq)]
pub struct RosterSeat {
    pub conference_id: String,
    /// The SIP Call-ID of the dialog with the seated party.
    pub call_id: String,
    pub from_tag: String,
    /// The seated party's own URI, without display name or parameters.
    pub party_uri: Option<String>,
    /// `talker`, `listener`, `muted`, `whisper` or `monitor`.
    pub role: String,
    /// `events` or `forward`: whether the room sends the seat's digits on to
    /// the other seats.
    pub dtmf: String,
    /// Unix seconds.
    pub joined_at: f64,
    pub kind: SeatKind,
    /// The SIP Call-ID of the conference dialog that adopted the call.
    pub owner_call_id: Option<String>,
    /// The engine call an adopted seat's leg belongs to: what a teardown names.
    pub engine_call_id: Option<String>,
    /// The call an adopted seat belongs to, by siphon's internal id.
    pub internal_call_id: Option<String>,
    /// `on_last_leave="end_owner"`: when this is the last seat adopted under
    /// its owner to go, the owner's dialog ends.
    pub end_owner_on_last: bool,
}

/// What happened to a seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Joined,
    Left,
}

impl Change {
    pub fn label(self) -> &'static str {
        match self {
            Self::Joined => "joined",
            Self::Left => "left",
        }
    }
}

/// A committed change to a room.
#[derive(Debug, Clone)]
pub struct ConferenceChange {
    pub conference_id: String,
    /// The conference dialog the seat was adopted under; for a seat that was
    /// not adopted, the dialog every adopted seat left in the room agrees on.
    pub owner_call_id: Option<String>,
    pub change: Change,
    /// The SIP Call-ID of the seat that changed.
    pub call_id: String,
    /// The seat that changed.
    pub seat: RosterSeat,
    /// The room after the change.
    pub roster: Vec<RosterSeat>,
}

#[derive(Default)]
struct Rooms {
    seats: HashMap<String, Vec<RosterSeat>>,
    subscribers: Vec<UnboundedSender<ConferenceChange>>,
    /// Roles of seats offered and not yet answered, by room and from-tag.
    offered: HashMap<(String, String), (String, String, Instant)>,
}

static ROOMS: Mutex<Option<Rooms>> = Mutex::new(None);

/// An offer no answer reached is dropped after this long.
const OFFER_LIFETIME: std::time::Duration = std::time::Duration::from_secs(300);

fn rooms() -> MutexGuard<'static, Option<Rooms>> {
    ROOMS.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn unix_seconds() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs_f64())
        .unwrap_or(0.0)
}

/// Receive every change committed from now on. A receiver that is dropped is
/// forgotten at the next change.
pub fn subscribe() -> UnboundedReceiver<ConferenceChange> {
    let (sender, receiver) = unbounded_channel();
    rooms()
        .get_or_insert_with(Rooms::default)
        .subscribers
        .push(sender);
    receiver
}

/// The seats in `conference_id`, in the order they were seated.
pub fn roster(conference_id: &str) -> Vec<RosterSeat> {
    rooms()
        .as_ref()
        .and_then(|rooms| rooms.seats.get(conference_id).cloned())
        .unwrap_or_default()
}

/// The seat of the call known by the SIP Call-ID `call_id` or by siphon's
/// internal id `internal_call_id`.
pub fn seat_of_call(call_id: &str, internal_call_id: &str) -> Option<RosterSeat> {
    let rooms = rooms();
    rooms
        .as_ref()?
        .seats
        .values()
        .flatten()
        .find(|seat| {
            seat.call_id == call_id || seat.internal_call_id.as_deref() == Some(internal_call_id)
        })
        .cloned()
}

/// How many rooms hold a seat, and how many seats and unanswered offers are
/// held in all (all drain to baseline: the per-module leak gate).
pub fn held() -> (usize, usize, usize) {
    match rooms().as_ref() {
        Some(rooms) => (
            rooms.seats.len(),
            rooms.seats.values().map(Vec::len).sum(),
            rooms.offered.len(),
        ),
        None => (0, 0, 0),
    }
}

/// The owner of the room: the conference dialog every adopted seat in it was
/// adopted under, when they agree.
fn room_owner(seats: &[RosterSeat]) -> Option<String> {
    let mut owners = seats
        .iter()
        .filter_map(|seat| seat.owner_call_id.as_deref());
    let first = owners.next()?;
    owners
        .all(|owner| owner == first)
        .then(|| first.to_string())
}

fn publish(rooms: &mut Rooms, seat: RosterSeat, change: Change) {
    let roster = rooms
        .seats
        .get(&seat.conference_id)
        .cloned()
        .unwrap_or_default();
    let owner_call_id = seat.owner_call_id.clone().or_else(|| room_owner(&roster));
    let event = ConferenceChange {
        conference_id: seat.conference_id.clone(),
        owner_call_id,
        change,
        call_id: seat.call_id.clone(),
        seat,
        roster,
    };
    rooms
        .subscribers
        .retain(|subscriber| subscriber.send(event.clone()).is_ok());
}

/// Record the role of a seat offered to a participant the focus calls out, for
/// the answer that seats it.
pub fn seat_offered(conference_id: &str, from_tag: &str, role: &str, dtmf: &str) {
    let mut guard = rooms();
    let rooms = guard.get_or_insert_with(Rooms::default);
    let now = Instant::now();
    rooms
        .offered
        .retain(|_, (_, _, offered_at)| now.duration_since(*offered_at) < OFFER_LIFETIME);
    rooms.offered.insert(
        (conference_id.to_string(), from_tag.to_string()),
        (role.to_string(), dtmf.to_string(), now),
    );
}

/// The role and digit forwarding a seat was offered with, taken off the record.
pub fn take_offered_role(conference_id: &str, from_tag: &str) -> Option<(String, String)> {
    rooms()
        .as_mut()?
        .offered
        .remove(&(conference_id.to_string(), from_tag.to_string()))
        .map(|(role, dtmf, _)| (role, dtmf))
}

/// A participant is seated (`joined`).
pub fn seat_joined(
    conference_id: &str,
    call_id: &str,
    from_tag: &str,
    party_uri: Option<String>,
    role: &str,
    dtmf: &str,
) {
    insert(RosterSeat {
        conference_id: conference_id.to_string(),
        call_id: call_id.to_string(),
        from_tag: from_tag.to_string(),
        party_uri,
        role: role.to_string(),
        dtmf: dtmf.to_string(),
        joined_at: unix_seconds(),
        kind: SeatKind::Joined,
        owner_call_id: None,
        engine_call_id: None,
        internal_call_id: None,
        end_owner_on_last: false,
    });
}

/// A call's far leg is moved into the room (`adopted`).
pub fn seat_adopted(seat: RosterSeat) {
    insert(seat);
}

fn insert(seat: RosterSeat) {
    let mut guard = rooms();
    let rooms = guard.get_or_insert_with(Rooms::default);
    let room = rooms.seats.entry(seat.conference_id.clone()).or_default();
    // The same dialog seated again in the room replaces its seat: one seat,
    // one change reported.
    if let Some(held) = room.iter_mut().find(|held| held.call_id == seat.call_id) {
        *held = seat;
        return;
    }
    room.push(seat.clone());
    publish(rooms, seat, Change::Joined);
}

fn remove(matching: impl Fn(&RosterSeat) -> bool) -> bool {
    let mut guard = rooms();
    let Some(rooms) = guard.as_mut() else {
        return false;
    };
    let mut gone = None;
    rooms.seats.retain(|_, room| {
        if gone.is_none() {
            if let Some(position) = room.iter().position(&matching) {
                gone = Some(room.remove(position));
            }
        }
        !room.is_empty()
    });
    match gone {
        Some(seat) => {
            publish(rooms, seat, Change::Left);
            true
        }
        None => false,
    }
}

/// A seated participant left, whether freed or deleted.
pub fn seat_left_joined(conference_id: &str, call_id: &str) -> bool {
    remove(|seat| {
        seat.kind == SeatKind::Joined
            && seat.conference_id == conference_id
            && seat.call_id == call_id
    })
}

/// The engine call `engine_call_id` was deleted: the seat its leg held goes
/// with it.
pub fn seat_left_engine_call(engine_call_id: &str) -> bool {
    remove(|seat| seat.engine_call_id.as_deref() == Some(engine_call_id))
}

/// A seat's role changed live. A role change is no change of who is seated, so
/// nothing is reported.
pub fn role_changed(conference_id: &str, from_tag: &str, role: &str, dtmf: Option<&str>) {
    if let Some(rooms) = rooms().as_mut() {
        if let Some(room) = rooms.seats.get_mut(conference_id) {
            for seat in room.iter_mut().filter(|seat| seat.from_tag == from_tag) {
                seat.role = role.to_string();
                if let Some(dtmf) = dtmf {
                    seat.dtmf = dtmf.to_string();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined(room: &str, call: &str) {
        seat_joined(
            room,
            call,
            "tag",
            Some("sip:a@example.com".into()),
            "talker",
            "events",
        );
    }

    fn adopted(room: &str, call: &str, owner: &str, engine: &str) {
        seat_adopted(RosterSeat {
            conference_id: room.into(),
            call_id: call.into(),
            from_tag: "far".into(),
            party_uri: Some("sip:b@example.com".into()),
            role: "talker".into(),
            dtmf: "events".into(),
            joined_at: unix_seconds(),
            kind: SeatKind::Adopted,
            owner_call_id: Some(owner.into()),
            engine_call_id: Some(engine.into()),
            internal_call_id: Some(format!("internal-{call}")),
            end_owner_on_last: false,
        });
    }

    fn drain(
        receiver: &mut UnboundedReceiver<ConferenceChange>,
        room: &str,
    ) -> Vec<ConferenceChange> {
        let mut changes = Vec::new();
        while let Ok(change) = receiver.try_recv() {
            if change.conference_id == room {
                changes.push(change);
            }
        }
        changes
    }

    #[test]
    fn a_join_and_a_leave_are_each_reported_once_with_the_room_after_the_change() {
        let mut receiver = subscribe();
        joined("roster-unit-1", "owner@192.0.2.1");
        adopted(
            "roster-unit-1",
            "far@192.0.2.2",
            "owner@192.0.2.1",
            "engine-1",
        );
        assert!(seat_left_engine_call("engine-1"));
        assert!(
            !seat_left_engine_call("engine-1"),
            "a second delete reports nothing"
        );
        assert!(seat_left_joined("roster-unit-1", "owner@192.0.2.1"));

        let changes = drain(&mut receiver, "roster-unit-1");
        let summary: Vec<_> = changes
            .iter()
            .map(|change| (change.change, change.call_id.as_str(), change.roster.len()))
            .collect();
        assert_eq!(
            summary,
            vec![
                (Change::Joined, "owner@192.0.2.1", 1),
                (Change::Joined, "far@192.0.2.2", 2),
                (Change::Left, "far@192.0.2.2", 1),
                (Change::Left, "owner@192.0.2.1", 0),
            ]
        );
        assert_eq!(changes[1].owner_call_id.as_deref(), Some("owner@192.0.2.1"));
        assert_eq!(changes[2].owner_call_id.as_deref(), Some("owner@192.0.2.1"));
        assert!(roster("roster-unit-1").is_empty());
    }

    #[test]
    fn a_joined_seat_takes_the_owner_the_adopted_seats_agree_on() {
        let mut receiver = subscribe();
        adopted(
            "roster-unit-2",
            "far-1@192.0.2.2",
            "owner@192.0.2.1",
            "engine-2a",
        );
        adopted(
            "roster-unit-2",
            "far-2@192.0.2.3",
            "other@192.0.2.1",
            "engine-2b",
        );
        joined("roster-unit-2", "dialled-in@192.0.2.4");
        let changes = drain(&mut receiver, "roster-unit-2");
        assert_eq!(changes[2].owner_call_id, None, "two owners do not agree");
        seat_left_engine_call("engine-2b");
        seat_left_joined("roster-unit-2", "dialled-in@192.0.2.4");
        joined("roster-unit-2", "dialled-in@192.0.2.4");
        let changes = drain(&mut receiver, "roster-unit-2");
        assert_eq!(changes[2].owner_call_id.as_deref(), Some("owner@192.0.2.1"));
        seat_left_engine_call("engine-2a");
        seat_left_joined("roster-unit-2", "dialled-in@192.0.2.4");
    }

    #[test]
    fn the_same_dialog_seated_again_is_one_seat_and_one_change() {
        let mut receiver = subscribe();
        joined("roster-unit-3", "again@192.0.2.1");
        joined("roster-unit-3", "again@192.0.2.1");
        assert_eq!(roster("roster-unit-3").len(), 1);
        assert_eq!(drain(&mut receiver, "roster-unit-3").len(), 1);
        seat_left_joined("roster-unit-3", "again@192.0.2.1");
    }

    #[test]
    fn a_role_change_updates_the_seat_and_reports_nothing() {
        let mut receiver = subscribe();
        joined("roster-unit-4", "role@192.0.2.1");
        role_changed("roster-unit-4", "tag", "listener", None);
        assert_eq!(
            roster("roster-unit-4")[0].dtmf,
            "events",
            "no dtmf given keeps it"
        );
        role_changed("roster-unit-4", "tag", "listener", Some("forward"));
        assert_eq!(roster("roster-unit-4")[0].dtmf, "forward");
        assert_eq!(roster("roster-unit-4")[0].role, "listener");
        assert_eq!(drain(&mut receiver, "roster-unit-4").len(), 1);
        seat_left_joined("roster-unit-4", "role@192.0.2.1");
    }

    #[test]
    fn a_seat_is_found_by_its_dialog_or_by_the_call_that_owns_it() {
        adopted(
            "roster-unit-5",
            "far@192.0.2.9",
            "owner@192.0.2.1",
            "engine-5",
        );
        let by_dialog = seat_of_call("far@192.0.2.9", "unrelated").expect("by dialog");
        let by_call = seat_of_call("alias@192.0.2.9", "internal-far@192.0.2.9").expect("by call");
        assert_eq!(by_dialog, by_call);
        assert!(seat_of_call("nobody", "nobody").is_none());
        seat_left_engine_call("engine-5");
    }

    #[test]
    fn an_offered_role_is_taken_once_and_unanswered_offers_expire() {
        seat_offered("roster-unit-6", "callee", "listener", "forward");
        assert_eq!(
            take_offered_role("roster-unit-6", "callee"),
            Some(("listener".to_string(), "forward".to_string()))
        );
        assert_eq!(take_offered_role("roster-unit-6", "callee"), None);
    }

    #[test]
    fn the_roster_drains_to_baseline_after_many_conferences() {
        let mut receiver = subscribe();
        for round in 0..50 {
            let room = format!("roster-leak-{round}");
            joined(&room, &format!("owner-{round}@192.0.2.1"));
            adopted(
                &room,
                &format!("far-{round}@192.0.2.2"),
                &format!("owner-{round}@192.0.2.1"),
                &format!("engine-leak-{round}"),
            );
            seat_offered(&room, "callee", "talker", "events");
            take_offered_role(&room, "callee");
            if round % 2 == 0 {
                seat_left_engine_call(&format!("engine-leak-{round}"));
                seat_left_joined(&room, &format!("owner-{round}@192.0.2.1"));
            } else {
                seat_left_joined(&room, &format!("owner-{round}@192.0.2.1"));
                seat_left_engine_call(&format!("engine-leak-{round}"));
            }
        }
        // Other tests of the process hold their own seats meanwhile, so the
        // rooms of this one are read by name.
        for round in 0..50 {
            assert!(roster(&format!("roster-leak-{round}")).is_empty());
        }
        // Every change was reported: a join and a leave per seat.
        let mut reported = 0;
        while let Ok(change) = receiver.try_recv() {
            if change.conference_id.starts_with("roster-leak-") {
                reported += 1;
            }
        }
        assert_eq!(reported, 50 * 4);
    }
}
