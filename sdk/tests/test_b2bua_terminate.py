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

    def test_reset_clears_recorded_terminates(self, harness):
        import siphon

        siphon.b2bua.terminate("x@example.com")
        assert harness.b2bua.terminates
        harness.reset()
        assert harness.b2bua.terminates == []
