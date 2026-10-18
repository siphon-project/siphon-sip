"""The recording and digit verbs of the rtpengine mock mirror the namespace."""
import asyncio

import pytest

from siphon_sdk.mock_module import MockRtpEngine


def run(coroutine):
    return asyncio.run(coroutine)


def test_record_returns_the_finished_file():
    engine = MockRtpEngine()
    target = ("call-1", "tag-1")
    engine.finish_recording("rec-1", path="/spool/m1.wav", duration_ms=4200,
                            reason="silence")
    result = run(engine.record(target, path="/spool/m1.wav",
                               max_duration_ms=120000, silence_ms=5000))
    assert result == {"recording_id": "rec-1", "path": "/spool/m1.wav",
                      "duration_ms": 4200, "reason": "silence"}
    assert engine.media_calls[-1]["op"] == "start_recording"
    assert engine.media_calls[-1]["silence_ms"] == 5000


def test_a_recording_not_reported_finished_is_none():
    engine = MockRtpEngine()
    recording_id = run(engine.start_recording(("c", "f")))
    assert run(engine.wait_recording(("c", "f"), recording_id)) is None
    assert run(engine.stop_recording(("c", "f"), recording_id))


def test_bad_recording_options_raise():
    engine = MockRtpEngine()
    with pytest.raises(ValueError):
        run(engine.start_recording(("c", "f"), direction="inbound"))


def test_read_digits_returns_digits_and_reason():
    engine = MockRtpEngine()
    engine.key_digits("c", "123#4")
    assert run(engine.read_digits(("c", "f"))) == ("123", "terminator")
    assert run(engine.read_digits(("c", "f"), max_digits=1)) == ("4", "max_digits")
    assert run(engine.read_digits(("c", "f"))) == ("", "timeout")
