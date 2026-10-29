"""Tests for the conference verbs of the ``rtpengine`` mock, and the focus in
examples/conference_focus.py driven through them.

A conference focus seats each participant's INVITE in a room of the media
engine's mixer and answers it with the engine's SDP; a BYE frees the seat.
The mock keeps the rooms, so a script author can assert the roster, a mute,
a bridge and a room playback without an engine.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.call import Call
from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["conference.example.com"])
    yield h
    h.reset()
    h.close()


def participant(number: int, room: str = "room-1") -> Call:
    return Call(
        call_id=f"participant-{number}@example.com",
        from_uri=f"sip:user{number}@example.com",
        ruri=f"sip:{room}@conference.example.com",
        headers={"From": f"<sip:user{number}@example.com>;tag=tag-{number}"},
        body=b"v=0\r\nm=audio 30000 RTP/AVP 0 101\r\n",
    )


def run(coroutine):
    return asyncio.run(coroutine)


class TestFocus:
    def test_five_joins_seat_five_and_byes_free_them(self, harness):
        # The cookbook's focus, examples/conference_focus.py, as shipped.
        harness.load_script("../examples/conference_focus.py")
        calls = [participant(number) for number in range(1, 6)]
        for call in calls:
            result = harness.send_invite(call)
            assert result.status_code == 200
        room = harness.rtpengine.conferences["room-1"]
        assert sorted(room) == [f"tag-{number}" for number in range(1, 6)]
        assert all(seat["role"] == "talker" for seat in room.values())

        for call in calls[:4]:
            harness.send_bye(call)
        assert sorted(harness.rtpengine.conferences["room-1"]) == ["tag-5"]
        harness.send_bye(calls[4])
        assert "room-1" not in harness.rtpengine.conferences, "the room ends with its last seat"

    def test_the_factory_uri_mints_a_room(self, harness):
        harness.load_script("../examples/conference_focus.py")
        result = harness.send_invite(participant(1, room="conference-factory"))
        assert result.status_code == 200
        (room,) = harness.rtpengine.conferences
        assert room.startswith("room-") and room != "conference-factory"
        harness.send_bye(participant(1, room="conference-factory"))
        assert harness.rtpengine.conferences == {}, "the BYE left the minted room"

    def test_join_resolves_to_the_answer_sdp(self, harness):
        harness.rtpengine.set_conference_join_sdp("v=0\r\nm=audio 41000 RTP/AVP 8\r\n")
        sdp = run(harness.rtpengine.conference_join("room-1", participant(1)))
        assert sdp == "v=0\r\nm=audio 41000 RTP/AVP 8\r\n"
        assert harness.rtpengine.conference_seat("participant-1@example.com") == ("room-1", "tag-1")

    def test_an_unencodable_codec_is_a_value_error(self, harness):
        harness.rtpengine.set_conference_join_no_codec()
        with pytest.raises(ValueError, match="no encodable codec"):
            run(harness.rtpengine.conference_join("room-1", participant(1)))
        assert harness.rtpengine.conferences == {}

    def test_a_call_holds_one_seat(self, harness):
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        with pytest.raises(ValueError, match="already seated"):
            run(harness.rtpengine.conference_join("room-2", participant(1)))

    def test_delete_on_a_seated_call_leaves_its_room(self, harness):
        call = participant(1)
        run(harness.rtpengine.conference_join("room-1", call))
        run(harness.rtpengine.delete(call))
        assert harness.rtpengine.conferences == {}
        assert ("conference_leave", "room-1") in harness.rtpengine.operations


class TestRoles:
    def test_route_changes_a_seats_role(self, harness):
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        run(harness.rtpengine.conference_join("room-1", participant(2), role="listener"))
        run(harness.rtpengine.conference_route("room-1", ("participant-1@example.com", "tag-1"), "muted"))
        run(harness.rtpengine.conference_route("room-1", participant(2), "whisper", target="tag-1"))
        room = harness.rtpengine.conferences["room-1"]
        assert room["tag-1"]["role"] == "muted"
        assert room["tag-2"]["role"] == "whisper"
        assert room["tag-2"]["target"] == "tag-1"

    @pytest.mark.parametrize(
        "role, target, whisper_target",
        [
            ("whisper", None, None),
            ("monitor", None, "tag-2"),
            ("talker", "tag-2", None),
            ("whisper", "tag-2", "tag-3"),
            ("speaker", None, None),
        ],
    )
    def test_a_role_without_the_target_it_needs_is_refused(
        self, harness, role, target, whisper_target
    ):
        with pytest.raises(ValueError):
            run(harness.rtpengine.conference_join(
                "room-1", participant(1), role=role, target=target,
                whisper_target=whisper_target,
            ))

    def test_a_seat_the_room_does_not_hold_is_refused(self, harness):
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        with pytest.raises(RuntimeError, match="no such conference"):
            run(harness.rtpengine.conference_route("room-1", ("x@example.com", "nobody"), "muted"))
        with pytest.raises(RuntimeError, match="no such conference participant"):
            run(harness.rtpengine.conference_leave("room-1", ("x@example.com", "nobody")))
        with pytest.raises(TypeError):
            run(harness.rtpengine.conference_leave("room-1", "participant-1@example.com"))


class TestBridgeAndPlay:
    def test_bridge_links_two_live_rooms(self, harness):
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        run(harness.rtpengine.conference_join("room-2", participant(2, "room-2"), ))
        run(harness.rtpengine.conference_bridge("room-1", "room-2", direction="a_to_b"))
        assert harness.rtpengine.conference_bridges == [("room-1", "room-2", "a_to_b")]
        with pytest.raises(RuntimeError, match="do not exist"):
            run(harness.rtpengine.conference_bridge("room-1", "room-9"))
        with pytest.raises(ValueError):
            run(harness.rtpengine.conference_bridge("room-1", "room-2", direction="sideways"))

        run(harness.rtpengine.conference_leave("room-2", participant(2, "room-2")))
        assert harness.rtpengine.conference_bridges == [], "a bridge ends with either room"

    def test_play_returns_an_id_that_stop_and_gain_address(self, harness):
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        first = run(harness.rtpengine.conference_play("room-1", tone="425/200,0/200*2"))
        second = run(harness.rtpengine.conference_play("room-1", file="/prompts/moh.wav", repeat="inf"))
        assert first != second
        run(harness.rtpengine.conference_set_play_gain("room-1", second, -18))
        assert harness.rtpengine.conference_plays[second]["gain_decibels"] == -18
        run(harness.rtpengine.conference_stop_play("room-1", first))
        assert list(harness.rtpengine.conference_plays) == [second]
        run(harness.rtpengine.conference_stop_play("room-1"))
        assert harness.rtpengine.conference_plays == {}
        with pytest.raises(RuntimeError):
            run(harness.rtpengine.conference_stop_play("room-1", first))

    def test_play_needs_a_live_room_and_one_source(self, harness):
        with pytest.raises(RuntimeError, match="unknown conference"):
            run(harness.rtpengine.conference_play("room-1", tone="ringback_eu"))
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        with pytest.raises(ValueError):
            run(harness.rtpengine.conference_play("room-1"))
        with pytest.raises(ValueError):
            run(harness.rtpengine.conference_play("room-1", tone="ringback_eu", file="/x.wav"))


class TestEvents:
    def test_active_speaker_reaches_its_handlers_filtered_by_room(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_active_speaker
def any_room(conference_id, from_tag):
    log.info(f"floor {conference_id} {from_tag}")

@rtpengine.on_active_speaker(conference_id="room-1")
def one_room(conference_id, from_tag):
    log.info("room-1 only")
"""
        )
        assert harness.rtpengine.fire_active_speaker("room-1", "tag-3") == 2
        assert harness.rtpengine.fire_active_speaker("room-2", None) == 1
        messages = [message for _, message in harness.log.messages]
        assert "floor room-1 tag-3" in messages
        assert "floor room-2 None" in messages

    def test_a_rooms_play_finished_names_the_room_as_call_id(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_play_finished(call_id="room-1")
def ended(call_id, from_tag, play_id, reason, played_ms):
    log.info(f"room playback {play_id} {reason}")
"""
        )
        assert harness.rtpengine.fire_play_finished("room-1", "", 3) == 1
        assert "room playback 3 completed" in [message for _, message in harness.log.messages]


class TestDialOut:
    """``conference_offer`` / ``conference_answer``: a seat the focus calls
    out, and ``conference_unbridge``."""

    def test_offer_then_answer_seats_the_participant(self):
        import asyncio
        from siphon_sdk.mock_module import MockRtpEngine
        engine = MockRtpEngine()

        async def run():
            sdp = await engine.conference_offer("room-1", "carol")
            assert "m=audio" in sdp
            assert engine.conference_offers
            await engine.conference_answer("room-1", ("out-1@example.com", "carol"), "v=0\r\n")
            assert engine.conference_seat("out-1@example.com") == ("room-1", "carol")
            assert not engine.conference_offers
            with pytest.raises(ValueError):
                await engine.conference_answer("room-1", ("out-1@example.com", "carol"), "v=0\r\n")
            with pytest.raises(ValueError):
                await engine.conference_offer("room-1", "bad tag")

        asyncio.run(run())

    def test_an_answer_behind_nat_names_where_it_came_from(self):
        import asyncio
        from siphon_sdk.mock_module import MockRtpEngine
        engine = MockRtpEngine()

        async def run():
            await engine.conference_offer("room-3", "erin")
            with pytest.raises(ValueError):
                await engine.conference_answer(
                    "room-3", ("out-3@example.com", "erin"), "v=0\r\n",
                    received_from="not-an-address",
                )
            await engine.conference_answer(
                "room-3", ("out-3@example.com", "erin"), "v=0\r\n",
                received_from="198.51.100.20",
            )
            assert engine.conferences["room-3"]["erin"]["received_from"] == "198.51.100.20"

        asyncio.run(run())

    def test_an_unanswered_offer_is_left(self):
        import asyncio
        from siphon_sdk.mock_module import MockRtpEngine
        engine = MockRtpEngine()

        async def run():
            await engine.conference_offer("room-2", "dave")
            assert await engine.conference_leave("room-2", ("x@example.com", "dave"))
            assert not engine.conference_offers

        asyncio.run(run())

    def test_unbridge_undoes_a_bridge(self):
        import asyncio
        from siphon_sdk.mock_module import MockRtpEngine
        engine = MockRtpEngine()

        async def run():
            for room, tag in (("a", "x"), ("b", "y")):
                await engine.conference_offer(room, tag)
                await engine.conference_answer(room, (f"{tag}@example.com", tag), "v=0\r\n")
            await engine.conference_bridge("a", "b", "a_to_b")
            assert await engine.conference_unbridge("b", "a")
            assert engine.conference_bridges == []
            with pytest.raises(RuntimeError):
                await engine.conference_unbridge("a", "b")

        asyncio.run(run())


class TestRoomRecording:
    def test_a_room_recording_returns_the_closed_file(self, harness):
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        recording_id = run(harness.rtpengine.conference_start_recording(
            "room-1", path="/spool/room-1.wav", max_duration_ms=5000))
        assert run(harness.rtpengine.conference_wait_recording("room-1", recording_id)) is None
        harness.rtpengine.finish_recording(recording_id, path="/spool/room-1.wav",
                                           duration_ms=5000, reason="max_duration")
        ended = run(harness.rtpengine.conference_wait_recording("room-1", recording_id))
        assert ended["path"] == "/spool/room-1.wav"
        assert ended["reason"] == "max_duration"
        assert run(harness.rtpengine.conference_stop_recording("room-1"))

    def test_an_unknown_room_or_a_zero_limit_is_refused(self, harness):
        with pytest.raises(RuntimeError):
            run(harness.rtpengine.conference_start_recording("nowhere"))
        run(harness.rtpengine.conference_join("room-1", participant(1)))
        with pytest.raises(ValueError):
            run(harness.rtpengine.conference_start_recording("room-1", silence_ms=0))
