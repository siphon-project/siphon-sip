"""Tests for b2bua.bridge() / b2bua.unbridge() — joining two calls siphon owns.

Every other B2BUA verb acts on one call; ``bridge`` joins two, so the two
parties hear each other. ``call_id`` names the leg that keeps its media anchor
(its ports and everything attached to them); ``with_call_id`` names the leg
joined to it, whose own media session is deleted.

Both are awaitable: they resolve once the media has been re-pointed and the
first of the two RFC 3261 §14 re-INVITEs is on the wire — the far ends'
verdicts arrive later on the control rail (``ChannelBridged`` /
``BridgeFailed``). ``unbridge`` leaves both legs answered, owned and held
(RFC 3264 §8.4), never hung up — otherwise it would be indistinguishable from
two ``terminate`` calls.

The suite has no asyncio plugin, so coroutines are driven with
``asyncio.run(...)`` from plain sync tests, or by the harness' own loop when a
loaded script's handler is async.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestBridgeFromScript:
    def test_async_handler_bridges_the_answered_leg(self, harness):
        # Callback-and-connect: the parked caller is the anchor (it keeps its
        # media session), the leg that just answered joins it.  Awaiting the
        # verb also proves the mock is a coroutine — awaiting a plain bool
        # would raise TypeError here.
        harness.load_source(
            """
from siphon import b2bua

PARKED = "parked-caller@example.com"

@b2bua.on_answer
async def connect(call, reply):
    await b2bua.bridge(PARKED, call.call_id)
"""
        )

        result = harness.send_answer(call_id="callee-leg@example.com")
        assert result.call.call_id == "callee-leg@example.com"
        assert harness.b2bua.bridges == [
            {
                "call_id": "parked-caller@example.com",
                "with_call_id": "callee-leg@example.com",
                "on_peer_hangup": "hangup",
            }
        ]

    def test_supervisor_keeps_the_survivor_held(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_answer
async def connect(call, reply):
    await b2bua.bridge(call.call_id, "agent-leg@example.com",
                       on_peer_hangup="hold")
"""
        )

        harness.send_answer(call_id="supervisor-leg@example.com")
        assert harness.b2bua.bridges[-1]["on_peer_hangup"] == "hold"

    def test_unbridge_from_a_script_leaves_both_legs_up(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_answer
async def split(call, reply):
    await b2bua.unbridge(call.call_id, reason="supervisor split")
"""
        )

        harness.send_answer(call_id="bridged-leg@example.com")
        assert harness.b2bua.unbridges == [
            {
                "call_id": "bridged-leg@example.com",
                "reason": "supervisor split",
            }
        ]
        # An unbridge that hung the legs up would be two terminates.
        assert harness.b2bua.terminates == []


class TestImperativeBridge:
    def test_direct_call_returns_true_and_records(self, harness):
        import siphon

        result = asyncio.run(
            siphon.b2bua.bridge("a-leg@example.com", "b-leg@example.com")
        )
        assert result is True
        assert harness.b2bua.bridges[-1] == {
            "call_id": "a-leg@example.com",
            "with_call_id": "b-leg@example.com",
            "on_peer_hangup": "hangup",
        }

    def test_default_peer_hangup_policy_is_hangup(self, harness):
        import siphon

        asyncio.run(siphon.b2bua.bridge("a@example.com", "b@example.com"))
        assert harness.b2bua.bridges[-1]["on_peer_hangup"] == "hangup"

    def test_hold_policy_is_recorded(self, harness):
        import siphon

        asyncio.run(
            siphon.b2bua.bridge(
                "a@example.com", "b@example.com", on_peer_hangup="hold"
            )
        )
        assert harness.b2bua.bridges[-1]["on_peer_hangup"] == "hold"

    def test_unknown_policy_raises_with_the_engine_message(self, harness):
        # Guessing at a teardown policy is how calls get stranded, so an
        # unrecognised value is refused — with the engine's exact wording.
        import siphon

        with pytest.raises(ValueError) as excinfo:
            asyncio.run(
                siphon.b2bua.bridge(
                    "a@example.com", "b@example.com", on_peer_hangup="park"
                )
            )
        assert str(excinfo.value) == (
            "b2bua.bridge(on_peer_hangup=…) must be 'hangup' or 'hold' "
            "(got 'park')"
        )
        assert harness.b2bua.bridges == []


class TestImperativeUnbridge:
    def test_direct_call_returns_true_and_defaults_the_reason(self, harness):
        import siphon

        result = asyncio.run(siphon.b2bua.unbridge("a-leg@example.com"))
        assert result is True
        assert harness.b2bua.unbridges[-1] == {
            "call_id": "a-leg@example.com",
            "reason": "unbridged",
        }

    def test_explicit_reason_is_recorded(self, harness):
        import siphon

        asyncio.run(
            siphon.b2bua.unbridge("a-leg@example.com", reason="consult return")
        )
        assert harness.b2bua.unbridges[-1]["reason"] == "consult return"


class TestReset:
    def test_reset_clears_bridges_and_unbridges(self, harness):
        import siphon

        asyncio.run(siphon.b2bua.bridge("a@example.com", "b@example.com"))
        asyncio.run(siphon.b2bua.unbridge("a@example.com"))
        assert harness.b2bua.bridges and harness.b2bua.unbridges

        harness.reset()
        assert harness.b2bua.bridges == []
        assert harness.b2bua.unbridges == []
