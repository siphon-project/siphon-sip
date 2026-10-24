"""``scope=`` on ``rtpengine.offer`` / ``answer`` / ``delete`` and every other
media verb, and the ``scope`` keyword media event handlers may take."""

import asyncio

import pytest

from siphon_sdk.call import Call
from siphon_sdk.mock_module import MockRtpEngine


def run(coroutine):
    return asyncio.run(coroutine)


def test_each_leg_records_its_scope_and_reuses_its_own_profile():
    engine = MockRtpEngine()
    target = ("call-1", "tag-a")
    run(engine.offer(target, profile="access_v4", sdp="v=0\r\n", scope="orig"))
    run(engine.offer(target, profile="access_v6", sdp="v=0\r\n", scope="term"))
    run(engine.answer(target, sdp="v=0\r\n", scope="orig"))
    run(engine.delete("call-1"))
    assert engine.media_scopes == [
        ("offer", "orig"),
        ("offer", "term"),
        ("answer", "orig"),
        ("delete", None),
    ]
    assert ("answer", "access_v4") in engine.operations


@pytest.mark.parametrize("scope", ["", "has space", "semi;colon", "x" * 65])
def test_an_invalid_scope_is_refused(scope):
    engine = MockRtpEngine()
    with pytest.raises(ValueError):
        run(engine.offer(("call-1", "tag-a"), sdp="v=0\r\n", scope=scope))
    assert engine.media_scopes == []


def test_a_b2bua_call_takes_no_scope():
    engine = MockRtpEngine()
    with pytest.raises(ValueError, match="B2BUA"):
        run(engine.delete(Call(), scope="orig"))


def test_delete_call_takes_a_scope():
    engine = MockRtpEngine()
    run(engine.delete_call("call-1", scope="orig"))
    run(engine.delete_call("call-2"))
    assert engine.media_scopes == [("delete_call", "orig"), ("delete_call", None)]
    with pytest.raises(ValueError):
        run(engine.delete_call("call-3", scope="bad scope"))


def test_every_media_verb_takes_the_legs_scope():
    engine = MockRtpEngine()
    target = ("call-1", "tag-a")
    run(engine.offer(target, sdp="v=0\r\n", scope="orig"))
    run(engine.offer(target, sdp="v=0\r\n", scope="term"))
    engine.media_scopes.clear()
    run(engine.play_media(target, file="/prompts/a.wav", scope="orig"))
    run(engine.play_overlay(target, tone="ringback_eu", scope="term"))
    run(engine.stop_media(target, scope="orig"))
    run(engine.set_play_gain(target, 1, -6, scope="term"))
    run(engine.play_dtmf(target, "5", scope="orig"))
    for verb in (engine.silence_media, engine.unsilence_media,
                 engine.block_media, engine.unblock_media, engine.detach_ws_tee,
                 engine.detach_ws_bridge):
        run(verb(target, scope="term"))
    run(engine.echo(target, scope="orig"))
    recording_id = run(engine.start_recording(target, scope="orig"))
    run(engine.wait_recording(target, recording_id, scope="orig"))
    run(engine.stop_recording(target, scope="orig"))
    run(engine.read_digits(target, scope="term"))
    run(engine.subscribe_request("call-1", "tag-a", "tag-s", scope="orig"))
    run(engine.subscribe_answer("call-1", "tag-a", "tag-s", b"v=0\r\n", scope="orig"))
    run(engine.unsubscribe("call-1", "tag-a", "tag-s", scope="orig"))
    run(engine.attach_ws_tee(target, "ws://tee.example.com/s", scope="term"))
    run(engine.attach_ws_bridge(target, "ws://bridge.example.com/s", scope="term"))
    assert [scope for _, scope in engine.media_scopes] == [
        "orig", "term", "orig", "term", "orig",
        "term", "term", "term", "term", "term", "term",
        "orig", "orig", "orig", "orig", "term",
        "orig", "orig", "orig", "term", "term",
    ]


def test_a_verb_without_a_scope_finds_the_only_scoped_leg_and_no_other():
    engine = MockRtpEngine()
    target = ("call-1", "tag-a")
    run(engine.offer(target, sdp="v=0\r\n", scope="orig"))
    run(engine.play_media(target, file="/prompts/a.wav"))
    run(engine.offer(target, sdp="v=0\r\n", scope="term"))
    run(engine.play_media(target, file="/prompts/a.wav"))
    run(engine.delete("call-1"))
    run(engine.play_media(target, file="/prompts/a.wav"))
    played = [scope for verb, scope in engine.media_scopes if verb == "play_media"]
    assert played == ["orig", None, None]


def test_a_media_verb_scope_on_a_b2bua_call_is_refused():
    engine = MockRtpEngine()
    for verb in (engine.silence_media, engine.stop_media, engine.echo):
        with pytest.raises(ValueError, match="B2BUA"):
            run(verb(Call(), scope="orig"))
    with pytest.raises(ValueError):
        run(engine.play_dtmf(("call-1", "tag-a"), "5", scope="bad scope"))


def test_a_handler_that_takes_scope_gets_it_and_one_that_does_not_is_unchanged():
    engine = MockRtpEngine()
    seen = []

    @engine.on_dtmf
    def scoped(call_id, from_tag, digit, duration_ms, volume, scope=None):
        seen.append(("scoped", call_id, digit, scope))

    @engine.on_dtmf
    def plain(call_id, from_tag, digit, duration_ms, volume):
        seen.append(("plain", call_id, digit))

    @engine.on_media_timeout
    def timed_out(call_id, from_tag, **extra):
        seen.append(("timeout", call_id, extra.get("scope")))

    assert engine.fire_dtmf("call-1", "tag-a", "5", scope="orig") == 2
    assert engine.fire_dtmf("call-1", "tag-a", "7") == 2
    assert engine.fire_media_timeout("call-1", "tag-a", scope="term") == 1
    assert seen == [
        ("scoped", "call-1", "5", "orig"),
        ("plain", "call-1", "5"),
        ("scoped", "call-1", "7", None),
        ("plain", "call-1", "7"),
        ("timeout", "call-1", "term"),
    ]
