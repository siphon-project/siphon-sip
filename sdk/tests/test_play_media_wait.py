"""Tests for the blocking `rtpengine.play_media(wait=...)` sequencing.

With `wait=True` (default) the real runtime blocks until the prompt finishes, so
an IVR handler can `offer -> answer -> play -> echo` with no overlap. The mock
auto-completes (blocking is a runtime behavior) but records `wait` and preserves
call order, which is what an author test needs.
"""

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestPlayMediaWait:
    def test_play_before_echo_and_wait_defaults_true(self, harness):
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    await rtpengine.offer(call, profile="ivr")
    call.answer(200, "OK", body=b"v=0\\r\\n", content_type="application/sdp")
    await rtpengine.play_media(call, file="/prompts/welcome.wav")   # wait defaults True
    await rtpengine.echo(call)
"""
        )
        harness.send_invite(
            ruri="sip:echo@example.com", from_uri="sip:alice@example.com"
        )
        # The prompt is played before echo is enabled (no overlap).
        ops = [op for op, _ in harness.rtpengine.operations]
        assert ops == ["offer", "play_media", "echo"]
        play = [c for c in harness.rtpengine.media_calls if c["op"] == "play_media"][-1]
        assert play["wait"] is True
        assert play["file"] == "/prompts/welcome.wav"

    def test_wait_false_is_recorded(self, harness):
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    await rtpengine.play_media(call, file="/moh.wav", wait=False)   # fire-and-forget
"""
        )
        harness.send_invite(
            ruri="sip:x@example.com", from_uri="sip:alice@example.com"
        )
        play = [c for c in harness.rtpengine.media_calls if c["op"] == "play_media"][-1]
        assert play["wait"] is False
