"""Tests for the RFC 7866 recording awareness example
(examples/recording_awareness.py), driven through the SDK mocks.

A record-aware caller asks with a=recordpref, gets a=record in every answer
with the state as it is, toggles it with a re-INVITE that only changes the
preference (answered here, the callee told nothing), and is re-offered the
state when a recording ends by itself.
"""
import asyncio
import importlib.util
import pathlib

import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon_sdk.call import Call  # noqa: E402
from siphon_sdk.reoffer import Reoffer  # noqa: E402
from siphon_sdk.reply import Reply  # noqa: E402

EXAMPLE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "examples"
    / "recording_awareness.py"
)


def offer(version, preference=None):
    line = f"a=recordpref:{preference}\r\n" if preference else ""
    return (
        f"v=0\r\no=- 1 {version} IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n"
        f"m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n{line}"
    )


SESSION = (
    "v=0\r\no=- 7 3 IN IP4 198.51.100.1\r\ns=-\r\nc=IN IP4 198.51.100.1\r\nt=0 0\r\n"
    "m=audio 30000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
)


def load():
    spec = importlib.util.spec_from_file_location("recording_awareness_example", EXAMPLE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def example():
    mock_module.reset()
    yield load()
    mock_module.reset()


def answered_call(example, preference="on", aware=True):
    headers = {"Supported": "replaces, record-aware"} if aware else {}
    call = Call(call_id="rec-1@example.com", body=offer(1, preference).encode(), headers=headers)
    asyncio.run(example.new_call(call))
    reply = Reply(status_code=200, call_id=call.call_id, body=SESSION.encode())
    asyncio.run(example.answered(call, reply))
    return call, reply


def started(engine):
    return [op for op in engine.media_calls if op["op"] == "start_recording"]


def test_a_caller_that_asks_is_recorded_and_told_so(example):
    from siphon import rtpengine

    call, reply = answered_call(example)
    recordings = started(rtpengine)
    assert [(op["format"], op["channels"], op["direction"]) for op in recordings] == [
        ("ogg_opus", "stereo", "both")
    ]
    assert "a=record:on" in reply.body.decode()


def test_a_caller_that_does_not_ask_is_told_off_and_not_recorded(example):
    from siphon import rtpengine

    call, reply = answered_call(example, preference=None)
    assert started(rtpengine) == []
    assert "a=record:off" in reply.body.decode()


def test_a_caller_that_is_not_record_aware_is_not_told(example):
    call, reply = answered_call(example, aware=False)
    assert "a=record" not in reply.body.decode()


def test_a_preference_only_reinvite_is_answered_here_with_the_new_state(example):
    from siphon import rtpengine

    call, _ = answered_call(example)
    toggle = Reoffer(sdp=offer(2, "off"), previous_sdp=offer(1, "on"), session_sdp=SESSION)
    asyncio.run(example.reoffered(call, toggle))
    assert rtpengine.media_calls[-1]["op"] == "stop_recording"
    decision, answer = toggle.decision
    assert decision == "answer" and "a=record:off" in answer

    again = Reoffer(sdp=offer(3, "on"), previous_sdp=offer(2, "off"), session_sdp=answer)
    asyncio.run(example.reoffered(call, again))
    assert len(started(rtpengine)) == 2, "a new recording, a new file"
    assert "a=record:on" in again.decision[1]
    paths = [op["path"] for op in started(rtpengine)]
    assert paths[0] != paths[1]


def test_an_offer_that_changes_the_media_is_relayed(example):
    call, _ = answered_call(example)
    moved = Reoffer(sdp=offer(2, "off").replace("40000", "40002"), previous_sdp=offer(1, "on"),
                    session_sdp=SESSION)
    asyncio.run(example.reoffered(call, moved))
    assert moved.kind == "change"
    assert moved.decision == ("relay",)


def test_a_recording_that_ends_by_itself_is_reoffered_off(example):
    from siphon import b2bua, rtpengine

    call, _ = answered_call(example)
    b2bua.session_sdps[(call.call_id, "caller")] = SESSION + "a=record:on\r\n"
    recording_id = started(rtpengine)[0]["recording_id"]
    rtpengine.finish_recording(recording_id, path="/spool/x.opus", duration_ms=60000,
                               reason="max_duration")
    assert len(b2bua.reoffers) == 1
    assert "a=record:off" in b2bua.reoffers[-1]["sdp"]


def test_a_recording_ended_by_the_hang_up_is_not_reoffered(example):
    from siphon import b2bua, rtpengine

    call, _ = answered_call(example)
    recording_id = started(rtpengine)[0]["recording_id"]
    asyncio.run(example.recording_closed(call.call_id, "tag", recording_id, "/spool/x.opus",
                                         "call_ended", 60000))
    assert b2bua.reoffers == []
