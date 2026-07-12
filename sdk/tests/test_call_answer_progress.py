"""Tests for imperative UAS ``call.answer()`` and ``call.progress()``.

``answer()`` sends the final 2xx the moment it's called (not deferred to when
the handler returns), so an async handler can answer and then keep working —
play a prompt to completion, then start echo — without delaying the 200.
``progress()`` sends a 1xx (early media / ringback) without answering.
"""

import pytest

from siphon_sdk.call import Call
from siphon_sdk.testing import SipTestHarness


class TestCallAnswerProgress:
    def test_answer_records_and_marks_answered(self):
        call = Call()
        call.answer(200, "OK", body="v=0\r\n", content_type="application/sdp")
        assert call.state == "answered"
        action = call._actions[-1]
        assert action.kind == "answer"
        assert action.status_code == 200
        assert action.extras["body"] == b"v=0\r\n"
        assert action.extras["content_type"] == "application/sdp"

    def test_answer_rejects_non_2xx(self):
        call = Call()
        with pytest.raises(ValueError):
            call.answer(183, "Session Progress")

    def test_progress_records_provisional_without_answering(self):
        call = Call()
        call.progress(183, "Session Progress", body=b"v=0\r\n",
                      content_type="application/sdp")
        # A provisional does NOT answer the call.
        assert call.state != "answered"
        action = call._actions[-1]
        assert action.kind == "progress"
        assert action.status_code == 183
        assert action.extras["body"] == b"v=0\r\n"

    def test_progress_rejects_non_1xx(self):
        call = Call()
        with pytest.raises(ValueError):
            call.progress(200, "OK")


@pytest.fixture
def harness():
    h = SipTestHarness(local_domains=["example.com"])
    yield h
    h.reset()
    h.close()


class TestIvrSequencing:
    def test_answer_then_play_then_echo(self, harness):
        # The dialplan-style IVR shape: offer -> answer NOW -> play to
        # completion -> echo. The await on play parks the coroutine; the answer
        # is already on the wire.
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    await rtpengine.offer(call, profile="ivr")
    call.answer(200, "OK", body=b"v=0\\r\\n", content_type="application/sdp")
    await rtpengine.play_media(call, file="/prompts/welcome.wav")
    await rtpengine.echo(call)
"""
        )
        result = harness.send_invite(
            ruri="sip:echo@example.com", from_uri="sip:alice@example.com"
        )
        # The call was answered (last Call action), and stays answered.
        assert result.action == "answer"
        assert result.call.state == "answered"
        # Media ran: offer, then the prompt, then echo — all after the answer.
        ops = [op for op, _ in harness.rtpengine.operations]
        assert "offer" in ops
        assert "play_media" in ops
        assert "echo" in ops
