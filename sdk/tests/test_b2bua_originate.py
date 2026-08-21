"""Tests for b2bua.originate() — a call siphon places itself.

Unlike call.dial() (a B-leg off a call that already arrived), originate creates a
call from nothing: click-to-dial, callbacks, outbound notification. It returns as
soon as the INVITE is on the wire; ringing and answer arrive later through the
ordinary @b2bua.* handlers.
"""

from __future__ import annotations

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestB2buaOriginate:
    def test_returns_a_call_id_and_records_the_target(self, harness):
        import siphon

        call_id = siphon.b2bua.originate(
            to="sip:+14035551212@carrier.example",
            media=True,
        )
        assert isinstance(call_id, str) and call_id
        placed = harness.b2bua.originates[-1]
        assert placed["call_id"] == call_id
        assert placed["to"] == "sip:+14035551212@carrier.example"
        assert placed["media"] is True
        assert placed["timeout"] == 30

    def test_carries_the_full_outbound_identity(self, harness):
        import siphon

        siphon.b2bua.originate(
            to="sip:+14035551212@carrier.example",
            to_display="Callee",
            from_uri="sip:+14035550100@siphon.example",
            from_display="Reminders",
            p_asserted_identity="sip:+14035550100@siphon.example",
            privacy="restricted",
            next_hop="sip:gw.carrier.example:5060",
            headers={"X-Campaign": "reminder"},
            media=True,
            profile="voice_ai",
            ws_uri="ws://ai.invalid/{call_id}",
            timeout=45,
        )
        placed = harness.b2bua.originates[-1]
        assert placed["from_uri"] == "sip:+14035550100@siphon.example"
        assert placed["from_display"] == "Reminders"
        assert placed["to_display"] == "Callee"
        assert placed["p_asserted_identity"] == "sip:+14035550100@siphon.example"
        assert placed["privacy"] == "restricted"
        assert placed["next_hop"] == "sip:gw.carrier.example:5060"
        assert placed["headers"] == {"X-Campaign": "reminder"}
        assert placed["profile"] == "voice_ai"
        assert placed["ws_uri"] == "ws://ai.invalid/{call_id}"
        assert placed["timeout"] == 45

    def test_a_caller_supplied_offer_is_carried_verbatim(self, harness):
        import siphon

        offer = "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\n"
        siphon.b2bua.originate(to="sip:1@carrier.example", sdp=offer)
        placed = harness.b2bua.originates[-1]
        assert placed["sdp"] == offer
        assert placed["media"] is False

    def test_no_media_plan_is_a_hard_error(self, harness):
        # An INVITE with no offer and no anchor cannot answer the callee's own
        # offer, so it would connect a call with no audio.
        import siphon

        with pytest.raises(ValueError, match="media plan"):
            siphon.b2bua.originate(to="sip:1@carrier.example")
        assert harness.b2bua.originates == []

    def test_both_media_plans_is_a_hard_error(self, harness):
        import siphon

        with pytest.raises(ValueError, match="not both"):
            siphon.b2bua.originate(
                to="sip:1@carrier.example", sdp="v=0\r\n", media=True
            )
        assert harness.b2bua.originates == []

    def test_empty_offer_is_a_hard_error(self, harness):
        import siphon

        with pytest.raises(ValueError, match="must not be empty"):
            siphon.b2bua.originate(to="sip:1@carrier.example", sdp="   ")

    def test_unknown_privacy_value_is_a_hard_error(self, harness):
        # Guessing at a privacy setting is how identities leak.
        import siphon

        with pytest.raises(ValueError, match="privacy"):
            siphon.b2bua.originate(
                to="sip:1@carrier.example", media=True, privacy="maybe"
            )
        assert harness.b2bua.originates == []

    def test_originate_from_a_timer_handler(self, harness):
        # The real shape: an outbound reminder campaign driven by a timer, with
        # no inbound call anywhere in the picture — nothing about originate
        # needs a `call` object or an inbound INVITE in scope.
        from siphon_sdk.mock_module import get_registry

        harness.load_source(
            """
from siphon import b2bua, timer

@timer.every(seconds=60)
def reminders():
    b2bua.originate(
        to="sip:+14035551212@carrier.example",
        from_uri="sip:+14035550100@siphon.example",
        media=True,
    )
"""
        )
        handlers = get_registry().handlers.get("timer.every", [])
        assert len(handlers) == 1
        _filter, fn, _is_async, _metadata = handlers[0]
        fn()

        assert len(harness.b2bua.originates) == 1
        assert harness.b2bua.originates[0]["to"] == "sip:+14035551212@carrier.example"

    def test_returned_call_id_drives_terminate(self, harness):
        # The Call-ID originate returns is the handle for every other imperative
        # verb — that is what makes it useful without a `call` object in scope.
        import siphon

        call_id = siphon.b2bua.originate(to="sip:1@carrier.example", media=True)
        assert siphon.b2bua.terminate(call_id, reason="campaign done") is True
        assert harness.b2bua.terminates[-1] == {
            "call_id": call_id,
            "reason": "campaign done",
        }

    def test_reset_drains_recorded_originates(self, harness):
        import siphon

        siphon.b2bua.originate(to="sip:1@carrier.example", media=True)
        assert harness.b2bua.originates
        harness.reset()
        assert harness.b2bua.originates == []
