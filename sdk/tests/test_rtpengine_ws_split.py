"""``rtpengine.attach_ws_split`` / ``detach_ws_split`` and the split events,
against the mock: it models the engine's rules rather than recording calls and
saying yes, so a script that attaches on a call the engine would refuse fails
here too."""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness()
    h.reset()
    return h


@pytest.fixture
def engine(harness):
    return harness.rtpengine


def attach(engine, target=("call-1@example.com", "tag-a"), **kwargs):
    return asyncio.run(
        engine.attach_ws_split(target, "wss://bot.example.net/call", **kwargs)
    )


def detach(engine, target=("call-1@example.com", "tag-a")):
    return asyncio.run(engine.detach_ws_split(target))


class TestAttach:
    def test_attach_on_an_answered_call_isolates_it(self, engine):
        engine.anchor_call("call-1@example.com")
        assert attach(engine, sample_rate=24000, offerer_profile="denoise") is True
        split = engine.splits["call-1@example.com"]
        assert split["ws_uri"] == "wss://bot.example.net/call"
        assert split["sample_rate"] == 24000
        assert split["offerer_profile"] == "denoise"
        assert split["answerer_profile"] is None
        assert split["isolated"] is True
        assert ("attach_ws_split", "wss://bot.example.net/call") in engine.operations

    def test_the_default_rate_is_the_engines(self, engine):
        engine.anchor_call("call-1@example.com")
        attach(engine)
        assert engine.splits["call-1@example.com"]["sample_rate"] == 16000

    def test_a_call_the_engine_does_not_hold_is_refused_like_the_engine_does(self, engine):
        with pytest.raises(RuntimeError, match="unknown call: call-1@example.com") as raised:
            attach(engine)
        assert raised.value.token is None
        assert engine.splits == {}

    def test_an_offered_call_nobody_answered_is_refused(self, engine):
        asyncio.run(engine.offer(("call-1@example.com", "tag-a"), sdp="v=0\r\n"))
        with pytest.raises(RuntimeError, match="ws-split-not-answered") as raised:
            attach(engine)
        assert raised.value.token == "ws-split-not-answered"

    def test_an_answer_makes_the_call_splittable(self, engine):
        asyncio.run(engine.offer(("call-1@example.com", "tag-a"), sdp="v=0\r\n"))
        asyncio.run(engine.answer(("call-1@example.com", "tag-a"), sdp="v=0\r\n", to_tag="tag-b"))
        assert attach(engine) is True

    def test_a_call_the_engine_answered_itself_has_no_second_party(self, engine):
        engine.anchor_call("call-1@example.com", answered_locally=True)
        with pytest.raises(RuntimeError) as raised:
            attach(engine)
        assert raised.value.token == "ws-split-answer-local"

    def test_a_seated_leg_is_refused(self, engine):
        engine.anchor_call("call-1@example.com")
        asyncio.run(
            engine.conference_join("room-1", _participant("call-1@example.com", "tag-a"))
        )
        with pytest.raises(RuntimeError) as raised:
            attach(engine)
        assert raised.value.token == "ws-split-seated"

    def test_a_second_attach_is_refused_until_it_is_detached(self, engine):
        engine.anchor_call("call-1@example.com")
        attach(engine)
        with pytest.raises(RuntimeError) as raised:
            attach(engine)
        assert raised.value.token == "ws-split-already-bridged"
        detach(engine)
        assert attach(engine) is True

    @pytest.mark.parametrize("rate", [0, 11025, 12000, 32000, 44100, 96000])
    def test_a_rate_the_engine_does_not_serve_is_a_value_error(self, engine, rate):
        engine.anchor_call("call-1@example.com")
        with pytest.raises(ValueError, match=str(rate)):
            attach(engine, sample_rate=rate)
        assert engine.splits == {}

    def test_an_engine_without_the_feature_is_refused_clearly(self, engine):
        engine.anchor_call("call-1@example.com")
        engine.set_ws_split_supported(False)
        with pytest.raises(RuntimeError, match="ws_split") as raised:
            attach(engine)
        assert raised.value.token is None
        with pytest.raises(RuntimeError, match="ws_split"):
            detach(engine)

    def test_a_scripted_refusal_carries_its_token_once(self, engine):
        engine.anchor_call("call-1@example.com")
        engine.refuse_next_ws_split("ws-split-renegotiation")
        with pytest.raises(RuntimeError, match="attach_ws_split: ws-split-renegotiation: ") as raised:
            attach(engine)
        assert raised.value.token == "ws-split-renegotiation"
        assert attach(engine) is True


class TestDetach:
    def test_detach_gives_the_parties_each_other_back(self, engine):
        engine.anchor_call("call-1@example.com")
        attach(engine)
        assert detach(engine) is True
        assert engine.splits == {}

    def test_detach_is_idempotent(self, engine):
        engine.anchor_call("call-1@example.com")
        assert detach(engine) is True
        attach(engine)
        assert detach(engine) is True
        assert detach(engine) is True

    def test_detach_on_a_call_the_engine_does_not_hold_is_refused(self, engine):
        with pytest.raises(RuntimeError, match="unknown call"):
            detach(engine)


class TestEvents:
    def test_attach_delivers_started_to_the_handler(self, engine):
        seen = []

        @engine.on_ws_split_started
        def up(call_id, from_tag, stream_id, ws_uri, sample_rate):
            seen.append((call_id, from_tag, stream_id, ws_uri, sample_rate))

        engine.anchor_call("call-1@example.com")
        attach(engine, sample_rate=8000)
        assert seen == [
            ("call-1@example.com", "tag-a", "split-call-1@example.com",
             "wss://bot.example.net/call", 8000)
        ]

    @pytest.mark.parametrize(
        "reason,isolated",
        [
            ("ws_closed", True),
            ("ws_stopped", True),
            ("ws_error", True),
            ("renegotiated", True),
            ("restored", True),
            ("a_reason_from_a_newer_engine", True),
            ("detached", False),
            ("call_deleted", False),
        ],
    )
    def test_each_end_reason_reaches_the_handler_and_the_call_stays_isolated_after_all_but_two(
        self, engine, reason, isolated
    ):
        seen = []

        @engine.on_ws_split_ended
        def down(call_id, from_tag, stream_id, reason):
            seen.append((call_id, from_tag, stream_id, reason))

        engine.anchor_call("call-1@example.com")
        attach(engine)
        assert engine.fire_ws_split_ended("call-1@example.com", "tag-a", reason=reason) == 1
        assert seen == [("call-1@example.com", "tag-a", "split-call-1@example.com", reason)]
        if isolated:
            # The engine does not restore it by itself: still held, silent
            # until the script detaches.
            split = engine.splits["call-1@example.com"]
            assert split["isolated"] is True
            assert split["end_reason"] == reason
            assert detach(engine) is True
            assert "call-1@example.com" not in engine.splits
            assert len(seen) == 1, "an end already reported is not reported twice"
        else:
            assert "call-1@example.com" not in engine.splits

    def test_an_end_is_reported_once(self, engine):
        engine.anchor_call("call-1@example.com")
        attach(engine)
        engine.fire_ws_split_ended("call-1@example.com", "tag-a", reason="ws_error")
        with pytest.raises(RuntimeError, match="already ended"):
            engine.fire_ws_split_ended("call-1@example.com", "tag-a", reason="ws_closed")

    def test_an_end_needs_a_started_split(self, engine):
        with pytest.raises(RuntimeError, match="no split"):
            engine.fire_ws_split_ended("call-1@example.com", "tag-a", reason="ws_closed")

    def test_a_detach_delivers_detached(self, engine):
        seen = []

        @engine.on_ws_split_ended
        def down(call_id, from_tag, stream_id, reason):
            seen.append(reason)

        engine.anchor_call("call-1@example.com")
        attach(engine)
        detach(engine)
        assert seen == ["detached"]

    def test_deleting_the_call_ends_the_split(self, engine):
        seen = []

        @engine.on_ws_split_ended
        def down(call_id, from_tag, stream_id, reason):
            seen.append(reason)

        engine.anchor_call("call-1@example.com")
        attach(engine)
        asyncio.run(engine.delete_call("call-1@example.com"))
        assert seen == ["call_deleted"]
        assert engine.splits == {}

    def test_a_handler_can_detach_from_inside_the_hook(self, engine):
        """The recovery the engine's rule asks for: an end that left the call
        isolated is answered with a detach, from the hook itself."""
        done = []

        @engine.on_ws_split_ended
        async def down(call_id, from_tag, stream_id, reason):
            if reason not in ("detached", "call_deleted"):
                await engine.detach_ws_split((call_id, from_tag))
                done.append(reason)

        engine.anchor_call("call-1@example.com")
        attach(engine)
        engine.fire_ws_split_ended("call-1@example.com", "tag-a", reason="ws_error")
        assert done == ["ws_error"]
        assert engine.splits == {}

    def test_filters_scope_the_handler(self, engine):
        seen = []

        @engine.on_ws_split_ended(call_id="other@example.com")
        def down(call_id, from_tag, stream_id, reason):
            seen.append(call_id)

        engine.anchor_call("call-1@example.com")
        attach(engine)
        assert engine.fire_ws_split_ended("call-1@example.com", "tag-a", reason="ws_error") == 0
        assert seen == []

    def test_a_started_split_can_be_told_to_the_mock_by_the_engine(self, engine):
        """An engine-originated start (no attach through the mock): the split
        is then held, and its end is accepted."""
        seen = []

        @engine.on_ws_split_started
        def up(call_id, from_tag, stream_id, ws_uri, sample_rate):
            seen.append(stream_id)

        assert engine.fire_ws_split_started(
            "call-9@example.com", "tag-a", "split-call-9@example.com",
            "wss://bot.example.net/s", 16000,
        ) == 1
        assert seen == ["split-call-9@example.com"]
        assert engine.fire_ws_split_ended("call-9@example.com", "tag-a", reason="ws_closed") == 0
        assert engine.splits["call-9@example.com"]["isolated"] is True


def _participant(call_id, from_tag):
    from siphon_sdk.call import Call

    return (call_id, from_tag)
