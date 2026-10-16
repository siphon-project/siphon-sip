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

    def test_progress_records_the_scripts_headers(self):
        call = Call()
        call.progress(183, "Session Progress", body=b"v=0\r\n",
                      content_type="application/sdp",
                      headers={"P-Early-Media": "sendrecv"})
        assert call._actions[-1].extras["headers"] == {"P-Early-Media": "sendrecv"}

    def test_answer_and_reject_record_the_scripts_headers(self):
        call = Call()
        call.answer(200, "OK", headers={"X-Lab-Tag": "a"})
        assert call._actions[-1].extras["headers"] == {"X-Lab-Tag": "a"}
        call = Call()
        call.reject(480, "Temporarily Unavailable", headers={"Retry-After": "120"})
        assert call._actions[-1].extras == {"headers": {"Retry-After": "120"}}

    @pytest.mark.parametrize("name", ["Contact", "to", "RSeq", "Require", "k", "Content-Type"])
    def test_a_framework_owned_header_raises(self, name):
        for send in (
            lambda call: call.progress(183, "Session Progress", headers={name: "x"}),
            lambda call: call.answer(200, "OK", headers={name: "x"}),
            lambda call: call.reject(486, "Busy Here", headers={name: "x"}),
        ):
            call = Call()
            with pytest.raises(ValueError):
                send(call)
            assert call._actions == []

    def test_a_value_with_a_line_break_raises(self):
        with pytest.raises(ValueError):
            Call().progress(183, "Session Progress",
                            headers={"P-Early-Media": "sendrecv\r\nVia: x"})

    def test_a_value_that_is_not_a_string_raises_type_error(self):
        with pytest.raises(TypeError):
            Call().reject(503, "Service Unavailable", headers={"Retry-After": 120})


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


class TestUasContact:
    """``contact=`` / ``contact_params=``: the Contact a conference focus
    answers its factory URI with (RFC 4579 §5.1)."""

    def test_answer_records_the_focus_contact(self):
        call = Call()
        call.answer(200, "OK", body="v=0\r\n", content_type="application/sdp",
                    contact="sip:conf-7@conf.example.com", contact_params="isfocus")
        assert call._actions[-1].extras["contact"] == "<sip:conf-7@conf.example.com>;isfocus"

    def test_a_contact_named_on_progress_stays_on_the_answer(self):
        call = Call()
        call.progress(183, "Session Progress", contact="sip:conf-7@conf.example.com",
                      contact_params=";isfocus")
        call.answer(200, "OK")
        assert call._actions[-1].extras["contact"] == "<sip:conf-7@conf.example.com>;isfocus"

    def test_without_a_contact_siphon_keeps_its_own(self):
        call = Call()
        call.answer(200, "OK")
        assert call._actions[-1].extras["contact"] is None

    @pytest.mark.parametrize("contact, params", [
        ("<sip:conf-7@conf.example.com>", None),
        ("tel:+15550100", None),
        ("sip:conf-7@conf.example.com garbage", None),
        ("sip:conf-7@conf.example.com", "isfocus\r\nVia: x"),
        ("sip:conf-7@conf.example.com", "bad name"),
        (None, "isfocus"),
    ])
    def test_a_contact_siphon_would_not_advertise_raises(self, contact, params):
        call = Call()
        with pytest.raises(ValueError):
            call.answer(200, "OK", contact=contact, contact_params=params)
        with pytest.raises(ValueError):
            call.progress(183, "Session Progress", contact=contact, contact_params=params)
