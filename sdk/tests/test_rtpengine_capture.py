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


def test_a_recording_can_be_ogg_opus_with_a_bitrate():
    engine = MockRtpEngine()
    run(engine.start_recording(("c", "f"), format="ogg_opus", channels="stereo",
                               direction="both", bitrate_bps=24000))
    started = engine.media_calls[-1]
    assert (started["format"], started["bitrate_bps"]) == ("ogg_opus", 24000)
    run(engine.start_recording(("c", "f")))
    assert engine.media_calls[-1]["format"] == "wav"


@pytest.mark.parametrize("options", [
    {"format": "mp3"},
    {"bitrate_bps": 24000},
    {"format": "ogg_opus", "bitrate_bps": 1000},
])
def test_a_format_or_bitrate_the_engine_refuses_raises(options):
    engine = MockRtpEngine()
    with pytest.raises(ValueError):
        run(engine.start_recording(("c", "f"), **options))


def test_a_finished_recording_reaches_the_handlers_for_its_call():
    engine = MockRtpEngine()
    seen = []

    @engine.on_recording_finished
    def any_call(call_id, from_tag, recording_id, path, reason, duration_ms):
        seen.append(("any", call_id, recording_id, path, reason, duration_ms))

    @engine.on_recording_finished(call_id="other-call")
    def other_call(call_id, from_tag, recording_id, path, reason, duration_ms):
        seen.append(("other", call_id))

    recording_id = run(engine.start_recording(("call-1", "tag-1"), format="ogg_opus"))
    fired = engine.finish_recording(recording_id, path="/spool/call-1.opus",
                                    duration_ms=61000, reason="call_ended")
    assert fired == 1
    assert seen == [("any", "call-1", recording_id, "/spool/call-1.opus",
                     "call_ended", 61000)]
    assert run(engine.wait_recording(("call-1", "tag-1"), recording_id))["reason"] == "call_ended"
    engine.clear()
    assert engine.fire_recording_finished("call-1", "tag-1", "rec-9") == 0


def test_read_digits_returns_digits_and_reason():
    engine = MockRtpEngine()
    engine.key_digits("c", "123#4")
    assert run(engine.read_digits(("c", "f"))) == ("123", "terminator")
    assert run(engine.read_digits(("c", "f"), max_digits=1)) == ("4", "max_digits")
    assert run(engine.read_digits(("c", "f"))) == ("", "timeout")
