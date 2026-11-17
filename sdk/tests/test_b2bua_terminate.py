"""Tests for the imperative b2bua.terminate(call_id) hangup.

Unlike call.terminate() (deferred until its own handler returns), b2bua.terminate
acts immediately and is keyed by SIP Call-ID, so it works from an out-of-band
event callback like @rtpengine.on_dtmf — the echo/IVR '#' hangup case.
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


class TestB2buaTerminate:
    def test_records_call_id_and_reason(self, harness):
        harness.load_source(
            """
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    b2bua.terminate(call.call_id, reason="IVR done")
"""
        )
        # Call it directly on the namespace too (the mock returns True).
        import siphon

        assert siphon.b2bua.terminate("ivr@example.com") is True
        assert harness.b2bua.terminates[-1] == {
            "call_id": "ivr@example.com",
            "reason": "Normal Clearing",
        }

    def test_terminate_from_on_dtmf_end_digit(self, harness):
        # The real echo/IVR shape: '#' in an @rtpengine.on_dtmf handler hangs the
        # call up by call-id, with no stashed `call` object (cross-worker safe).
        harness.load_source(
            """
from siphon import rtpengine, b2bua

END_DIGIT = "#"

@rtpengine.on_dtmf
def on_ivr_dtmf(call_id, from_tag, digit, duration_ms, volume):
    if digit == END_DIGIT:
        b2bua.terminate(call_id)
"""
        )

        # A non-end digit does not terminate.
        harness.rtpengine.fire_dtmf("call-abc@example.com", "ft", "5")
        assert harness.b2bua.terminates == []

        # The end digit terminates by call-id.
        fired = harness.rtpengine.fire_dtmf("call-abc@example.com", "ft", "#")
        assert fired == 1
        assert harness.b2bua.terminates == [
            {"call_id": "call-abc@example.com", "reason": "Normal Clearing"}
        ]

    def test_terminate_takes_the_call_id_originate_returned(self, harness):
        # Ringing two of a user's clients and giving up on one while it rings:
        # the leg is named by the Call-ID b2bua.originate() returned. On a real
        # node that is a CANCEL of the leg's INVITE (RFC 3261 section 9.1).
        import siphon

        first = siphon.b2bua.originate("sip:alice@192.0.2.10", media=True)
        second = siphon.b2bua.originate("sip:alice@192.0.2.11", media=True)
        assert first != second

        assert siphon.b2bua.terminate(second, reason="answered elsewhere") is True
        assert harness.b2bua.terminates == [
            {"call_id": second, "reason": "answered elsewhere"}
        ]

    def test_docstring_says_what_goes_on_the_wire(self, harness):
        import siphon

        doc = siphon.b2bua.terminate.__doc__
        assert "CANCEL" in doc and "BYE" in doc and "9.1" in doc

    def test_reset_clears_recorded_terminates(self, harness):
        import siphon

        siphon.b2bua.terminate("x@example.com")
        assert harness.b2bua.terminates
        harness.reset()
        assert harness.b2bua.terminates == []
