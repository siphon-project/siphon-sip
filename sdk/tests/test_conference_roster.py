"""The conference roster: ``b2bua.conference_roster``, ``call.conference``,
``@b2bua.on_conference_change``, ``adopt_replaced(on_last_leave="end_owner")``
and ``proxy.subscribe_state.for_resource``.

A script that keeps no state of its own (module state is emptied on every
reload and a conference outlives a deploy) reads the room from siphon and is
told when it changes.
"""

from __future__ import annotations

import pytest

from siphon_sdk import mock_module
from siphon_sdk.call import Call
from siphon_sdk.mock_module import HeldLeg
from siphon_sdk.testing import SipTestHarness

SUBSCRIBER = "192.0.2.10:5060"
CARRIER = "198.51.100.77:5060"
ROOM = "room-1"
OWNER = "conf@192.0.2.10"

SCRIPT = """
import builtins
from siphon import b2bua

@b2bua.on_refer
async def on_refer(call):
    call.accept_refer(mode="script")
    status = await b2bua.adopt_replaced(call, "room-1", on_last_leave=builtins.ON_LAST_LEAVE)
    b2bua.complete_refer(call.call_id, status)

@b2bua.on_bye
def on_bye(call, initiator):
    builtins.BYE_SEEN.append(call.conference)
"""


@pytest.fixture
def harness():
    import builtins

    h = SipTestHarness(local_domains=["example.com"])
    builtins.ON_LAST_LEAVE = "end_owner"
    builtins.BYE_SEEN = []
    h.load_source(SCRIPT)
    yield h
    h.reset()
    h.close()


@pytest.fixture
def told():
    """What ``@b2bua.on_conference_change`` was told, as tuples."""
    events: list[tuple] = []

    def changed(conference_id, owner_call_id, change, call_id, roster):
        events.append((conference_id, owner_call_id, change, call_id,
                       [(seat["call_id"], seat["kind"]) for seat in roster]))

    mock_module.get_b2bua().on_conference_change(changed)
    return events


def leg(call_id, tag, source, uri, remote_tag):
    return HeldLeg(call_id=call_id, local_tag=tag, remote_tag=remote_tag,
                   source=source, uri=uri)


def held_call(name):
    return mock_module.get_b2bua().hold_call(
        leg(f"{name}-a@192.0.2.1", f"{name}-ours", SUBSCRIBER,
            "<sip:15550100001@example.com>", "subscriber-tag"),
        leg(f"{name}-b@192.0.2.1", f"{name}-carrier", CARRIER,
            "<sip:15550100042@carrier.example.com>", f"{name}-carrier-tag"),
    )


def owner_dialog():
    """The conference dialog: the subscriber's call to the focus, seated."""
    owner = Call(call_id=OWNER, state="answered",
                 from_uri="sip:15550100001@example.com", source_ip="192.0.2.10")
    owner.headers = {"From": "<sip:15550100001@example.com>;tag=owner-tag"}
    return owner


def seat_owner(harness):
    owner = owner_dialog()
    harness._loop.run_until_complete(
        mock_module.get_rtpengine().conference_join(ROOM, (OWNER, "owner-tag")))
    return owner


def merge(harness, held):
    call = Call(call_id=OWNER, state="answered", from_uri="sip:15550100001@example.com",
                source_ip="192.0.2.10", refer_to="sip:15550100042@example.com",
                refer_replaces=held.caller.replaces(), refer_side="a")
    harness.send_refer(call=call)
    return mock_module.get_b2bua().refer_reports[-1]["code"]


class TestRoster:
    def test_joined_and_adopted_seats_differ_in_kind_owner_and_party(self, harness, told):
        seat_owner(harness)
        held = held_call("one")
        assert merge(harness, held) == 200
        roster = mock_module.get_b2bua().conference_roster(ROOM)
        assert [seat["kind"] for seat in roster] == ["joined", "adopted"]
        joined, adopted = roster
        assert joined["call_id"] == OWNER
        assert joined["owner_call_id"] is None
        assert adopted["call_id"] == "one-b@192.0.2.1"
        assert adopted["party_uri"] == "sip:15550100042@carrier.example.com"
        assert adopted["owner_call_id"] == OWNER
        assert adopted["role"] == "talker"
        assert isinstance(adopted["joined_at"], float)
        assert set(adopted) == {"call_id", "from_tag", "party_uri", "role",
                                "joined_at", "kind", "owner_call_id"}

    def test_an_unknown_room_is_empty(self, harness):
        assert mock_module.get_b2bua().conference_roster("no-such-room") == []

    def test_call_conference_reads_in_on_bye(self, harness, told):
        import builtins

        builtins.ON_LAST_LEAVE = "keep"
        seat_owner(harness)
        held = held_call("bye")
        merge(harness, held)
        far = Call(call_id="bye-a@192.0.2.1", state="answered")
        harness.send_bye(call=far)
        assert builtins.BYE_SEEN == [(ROOM, OWNER)]
        assert far.conference is None, "the seat left with the call"
        joined = Call(call_id=OWNER, state="answered")
        assert joined.conference == (ROOM, None)
        assert Call(call_id="elsewhere@192.0.2.1", state="answered").conference is None


class TestChanges:
    def test_each_adopt_and_each_leave_is_one_event(self, harness, told):
        seat_owner(harness)
        first, second = held_call("first"), held_call("second")
        merge(harness, first)
        merge(harness, second)
        harness.send_bye(call=Call(call_id="first-a@192.0.2.1", state="answered"))
        assert [(event[2], event[3]) for event in told] == [
            ("joined", OWNER),
            ("joined", "first-b@192.0.2.1"),
            ("joined", "second-b@192.0.2.1"),
            ("left", "first-b@192.0.2.1"),
        ]
        assert told[1][1] == OWNER
        assert told[1][4] == [(OWNER, "joined"), ("first-b@192.0.2.1", "adopted")]
        assert told[3][4] == [(OWNER, "joined"), ("second-b@192.0.2.1", "adopted")]

    def test_the_owner_ending_leaves_one_event_per_adopted_seat(self, harness, told):
        seat_owner(harness)
        merge(harness, held_call("a"))
        merge(harness, held_call("b"))
        told.clear()
        assert len(mock_module.get_b2bua().conference_dialog_ended(OWNER)) == 2
        assert [event[2] for event in told] == ["left", "left"]
        assert [len(event[4]) for event in told] == [2, 1]

    def test_a_join_a_leave_and_a_delete_are_each_reported(self, harness, told):
        engine = mock_module.get_rtpengine()
        run = harness._loop.run_until_complete
        run(engine.conference_join(ROOM, ("guest-1@192.0.2.50", "tag-1")))
        run(engine.conference_join(ROOM, ("guest-2@192.0.2.51", "tag-2")))
        run(engine.conference_leave(ROOM, ("guest-1@192.0.2.50", "tag-1")))
        run(engine.delete(Call(call_id="guest-2@192.0.2.51", state="answered")))
        assert [(event[2], event[3]) for event in told] == [
            ("joined", "guest-1@192.0.2.50"),
            ("joined", "guest-2@192.0.2.51"),
            ("left", "guest-1@192.0.2.50"),
            ("left", "guest-2@192.0.2.51"),
        ]
        assert told[3][4] == []

    def test_an_async_handler_is_run_and_a_raise_is_swallowed(self, harness):
        seen = []

        async def async_changed(conference_id, owner_call_id, change, call_id, roster):
            seen.append(change)

        def raises(conference_id, owner_call_id, change, call_id, roster):
            raise RuntimeError("a script bug")

        b2bua = mock_module.get_b2bua()
        b2bua.on_conference_change(raises)
        b2bua.on_conference_change(async_changed)
        harness._loop.run_until_complete(
            mock_module.get_rtpengine().conference_join(ROOM, ("guest@192.0.2.50", "tag")))
        assert seen == ["joined"]
        assert len(b2bua.conference_change_errors) == 1

    def test_a_reload_changes_nothing(self, harness, told):
        seat_owner(harness)
        first, second = held_call("r1"), held_call("r2")
        merge(harness, first)
        before = mock_module.get_b2bua().conference_roster(ROOM)
        harness.load_source(SCRIPT)          # the deploy: handlers registered anew
        later = []

        def after(conference_id, owner_call_id, change, call_id, roster):
            later.append((change, call_id))

        mock_module.get_b2bua().on_conference_change(after)
        assert mock_module.get_b2bua().conference_roster(ROOM) == before
        merge(harness, second)
        assert later == [("joined", "r2-b@192.0.2.1")]


class TestEndOwner:
    def far_hangs_up(self, harness, name):
        harness.send_bye(call=Call(call_id=f"{name}-a@192.0.2.1", state="answered"))

    def test_the_last_adopted_call_leaving_ends_the_owner(self, harness, told):
        seat_owner(harness)
        merge(harness, held_call("x"))
        merge(harness, held_call("y"))
        self.far_hangs_up(harness, "x")
        assert mock_module.get_b2bua().terminates == []
        self.far_hangs_up(harness, "y")
        assert mock_module.get_b2bua().terminates == [
            {"call_id": OWNER, "reason": "Q.850;cause=16"}]
        # The owner's own seat leaves too, and is told.
        assert told[-1][2:4] == ("left", OWNER)
        assert mock_module.get_b2bua().conference_roster(ROOM) == []

    def test_the_default_keeps_the_owner(self, harness, told):
        import builtins

        builtins.ON_LAST_LEAVE = "keep"
        seat_owner(harness)
        merge(harness, held_call("k"))
        self.far_hangs_up(harness, "k")
        assert mock_module.get_b2bua().terminates == []
        assert [seat["call_id"] for seat in mock_module.get_b2bua().conference_roster(ROOM)] == [OWNER]

    def test_another_seat_keeps_the_owner(self, harness, told):
        seat_owner(harness)
        merge(harness, held_call("m"))
        harness._loop.run_until_complete(
            mock_module.get_rtpengine().conference_join(ROOM, ("guest@192.0.2.50", "tag")))
        self.far_hangs_up(harness, "m")
        assert mock_module.get_b2bua().terminates == []

    def test_the_owner_ending_first_is_not_ended_again(self, harness, told):
        seat_owner(harness)
        merge(harness, held_call("o"))
        mock_module.get_b2bua().conference_dialog_ended(OWNER)
        assert mock_module.get_b2bua().terminates == [
            {"call_id": "o-a@192.0.2.1", "reason": "Q.850;cause=16"}]

    def test_an_unknown_value_raises(self, harness):
        b2bua = mock_module.get_b2bua()
        held = held_call("v")
        call = Call(call_id=OWNER, state="answered", refer_to="sip:x@example.com",
                    refer_replaces=held.caller.replaces(), refer_side="a")
        with pytest.raises(ValueError, match="on_last_leave"):
            harness._loop.run_until_complete(
                b2bua.adopt_replaced(call, ROOM, on_last_leave="linger"))


class TestForResource:
    def subscribe(self, harness, to_uri, event="conference", call_id="sub-1"):
        from siphon_sdk.request import Request

        request = Request(method="SUBSCRIBE", ruri=to_uri, call_id=call_id,
                          from_uri="sip:15550100002@example.com", to_uri=to_uri,
                          event=event)
        return mock_module.get_proxy().subscribe_state.create(request)

    def test_lists_only_live_subscribers_of_that_resource_and_package(self, harness):
        state = mock_module.get_proxy().subscribe_state
        mine = self.subscribe(harness, "sip:room-1@conf.example.com", call_id="a")
        also = self.subscribe(harness, "sip:room-1@conf.example.com", "Conference;id=3", call_id="b")
        self.subscribe(harness, "sip:room-2@conf.example.com", call_id="c")
        self.subscribe(harness, "sip:room-1@conf.example.com", "presence", call_id="d")
        gone = self.subscribe(harness, "sip:room-1@conf.example.com", call_id="e")
        gone._dialog["terminated"] = True
        expired = self.subscribe(harness, "sip:room-1@conf.example.com", call_id="f")
        expired._dialog["expires_secs"] = 0

        found = state.for_resource("sip:room-1@conf.example.com", "conference")
        assert [handle.id for handle in found] == [mine.id, also.id]
        assert [handle.id for handle in
                state.for_resource("<sip:room-1@conf.example.com>", "CONFERENCE")] == [mine.id, also.id]
        assert state.for_resource("sip:room-9@conf.example.com", "conference") == []
        assert state.for_resource("sip:room-1x@conf.example.com", "conference") == []
