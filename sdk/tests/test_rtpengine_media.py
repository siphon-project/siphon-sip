"""Tests for MockRtpEngine media-injection methods.

Covers play_media/stop_media/play_dtmf/silence+unsilence/block+unblock/echo —
the announcement, DTMF, and echo-test surface added for MMTEL / TAS-style scripts.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.call import Call
from siphon_sdk.request import Request
from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness()
    h.reset()
    return h


class TestPlayMedia:
    def test_file_source_records_call(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, file="/var/lib/siphon/prompts/cfu.wav")
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        assert ("play_media", "file") in harness.rtpengine.operations
        call = harness.rtpengine.media_calls[-1]
        assert call["op"] == "play_media"
        assert call["file"] == "/var/lib/siphon/prompts/cfu.wav"
        assert call["blob"] is None
        assert call["db_id"] is None

    def test_blob_source_preserves_bytes(self, harness):
        # Binary payload with NUL and high bytes — proves bytes round-trip.
        tts_bytes = b"\x00\xffRIFF\xde\xad\xbe\xef"
        harness.load_source(
            f"""
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, blob={tts_bytes!r})
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        call = harness.rtpengine.media_calls[-1]
        assert call["op"] == "play_media"
        assert call["blob"] == tts_bytes

    def test_db_id_source(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, db_id=42, repeat=3)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        call = harness.rtpengine.media_calls[-1]
        assert call["db_id"] == 42
        assert call["repeat"] == 3

    def test_exactly_one_source_required(self, harness):
        with pytest.raises(ValueError, match="exactly one"):
            import asyncio
            asyncio.run(harness.rtpengine.play_media(None))

        with pytest.raises(ValueError, match="exactly one"):
            import asyncio
            asyncio.run(harness.rtpengine.play_media(None, file="/a.wav", blob=b"x"))

    def test_returns_configured_duration(self, harness):
        harness.rtpengine.set_play_media_duration(12345)
        import asyncio
        result = asyncio.run(
            harness.rtpengine.play_media(None, file="/a.wav")
        )
        assert result == 12345

    def test_to_tag_scoping_for_mpty(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, file="/x.wav", to_tag="peer-42")
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        call = harness.rtpengine.media_calls[-1]
        assert call["to_tag"] == "peer-42"


class TestStopMedia:
    def test_stop_media_recorded(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, file="/a.wav")
    await rtpengine.stop_media(request)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        ops = [name for name, _ in harness.rtpengine.operations]
        assert ops == ["play_media", "stop_media"]


class TestPlayDtmf:
    def test_dtmf_sequence_captured(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_dtmf(request, "123#", duration_ms=100, volume_dbm0=-8)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        assert ("play_dtmf", "123#") in harness.rtpengine.operations
        call = harness.rtpengine.media_calls[-1]
        assert call["op"] == "play_dtmf"
        assert call["code"] == "123#"
        assert call["duration_ms"] == 100
        assert call["volume_dbm0"] == -8


class TestSilenceAndBlock:
    def test_silence_pair(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.silence_media(request)
    await rtpengine.unsilence_media(request)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        ops = [name for name, _ in harness.rtpengine.operations]
        assert ops == ["silence_media", "unsilence_media"]

    def test_block_pair(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.block_media(request)
    await rtpengine.unblock_media(request)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        ops = [name for name, _ in harness.rtpengine.operations]
        assert ops == ["block_media", "unblock_media"]


class TestEcho:
    def test_echo_default_enabled(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.echo(request)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        assert ("echo", True) in harness.rtpengine.operations
        call = harness.rtpengine.media_calls[-1]
        assert call["op"] == "echo"
        assert call["enabled"] is True

    def test_echo_disabled(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.echo(request, enabled=False)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        assert ("echo", False) in harness.rtpengine.operations
        call = harness.rtpengine.media_calls[-1]
        assert call["enabled"] is False


class TestClear:
    def test_clear_resets_media_state(self, harness):
        import asyncio
        asyncio.run(harness.rtpengine.play_media(None, file="/a.wav"))
        assert harness.rtpengine.operations
        assert harness.rtpengine.media_calls
        harness.rtpengine.clear()
        assert harness.rtpengine.operations == []
        assert harness.rtpengine.media_calls == []


class TestOnMediaTimeout:
    def test_catch_all_and_filtered_dispatch(self, harness):
        harness.load_source(
            """
from siphon import rtpengine

fired = []

@rtpengine.on_media_timeout
def any_timeout(call_id, from_tag):
    fired.append(("any", call_id, from_tag))

@rtpengine.on_media_timeout(call_id="abc", from_tag="ftag1")
def specific_timeout(call_id, from_tag):
    fired.append(("specific", call_id, from_tag))
"""
        )
        # Exact match → both the catch-all and the filtered handler fire.
        assert harness.rtpengine.fire_media_timeout("abc", "ftag1") == 2
        # Non-matching call → only the catch-all.
        assert harness.rtpengine.fire_media_timeout("xyz", "other") == 1
        # Right call-id, wrong from-tag → catch-all only.
        assert harness.rtpengine.fire_media_timeout("abc", "wrong") == 1

    def test_no_handlers_fires_nothing(self, harness):
        harness.load_source(
            """
from siphon import proxy

@proxy.on_request
def route(request):
    request.reply(200, "OK")
"""
        )
        assert harness.rtpengine.fire_media_timeout("abc", "ftag1") == 0


class TestAnswerLocal:
    def test_success_returns_answer_sdp(self, harness):
        call = Call()
        sdp = asyncio.run(harness.rtpengine.answer_local(call))
        assert sdp == "v=0\r\nm=audio 40000 RTP/AVP 8 101\r\n"
        # No prior offer → default profile.
        assert ("answer_local", "rtp_passthrough") in harness.rtpengine.operations

    def test_configured_answer_sdp(self, harness):
        harness.rtpengine.set_answer_local_sdp("v=0\r\nm=audio 5004 RTP/AVP 0\r\n")
        sdp = asyncio.run(harness.rtpengine.answer_local(Call()))
        assert sdp == "v=0\r\nm=audio 5004 RTP/AVP 0\r\n"

    def test_profile_recovered_from_offer(self, harness):
        call = Call()
        asyncio.run(harness.rtpengine.offer(call, profile="ivr"))
        asyncio.run(harness.rtpengine.answer_local(call))
        assert ("answer_local", "ivr") in harness.rtpengine.operations

    def test_explicit_profile_wins(self, harness):
        call = Call()
        asyncio.run(harness.rtpengine.offer(call, profile="ivr"))
        asyncio.run(harness.rtpengine.answer_local(call, profile="rtp_passthrough"))
        assert ("answer_local", "rtp_passthrough") in harness.rtpengine.operations

    def test_no_codec_auto_reject_sets_488_and_returns_none(self, harness):
        call = Call()
        harness.rtpengine.set_answer_local_no_codec()
        result = asyncio.run(harness.rtpengine.answer_local(call))
        assert result is None
        action = call._actions[-1]
        assert action.kind == "reject"
        assert action.status_code == 488
        assert action.reason == "Not Acceptable Here"
        assert call.state == "terminated"

    def test_no_codec_auto_reject_false_raises_value_error(self, harness):
        harness.rtpengine.set_answer_local_no_codec()
        with pytest.raises(ValueError, match="no encodable codec"):
            asyncio.run(harness.rtpengine.answer_local(Call(), auto_reject=False))

    def test_no_codec_non_call_target_raises_value_error(self, harness):
        # A Request has no reject channel, so even auto_reject=True raises.
        harness.rtpengine.set_answer_local_no_codec()
        with pytest.raises(ValueError, match="no encodable codec"):
            asyncio.run(harness.rtpengine.answer_local(Request(method="INVITE")))

    def test_driven_from_on_invite_handler(self, harness):
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    sdp = await rtpengine.answer_local(call, profile="ivr")
    if sdp is not None:
        call.answer(200, "OK", body=sdp, content_type="application/sdp")
"""
        )
        result = harness.send_invite(
            ruri="sip:echo@example.com", from_uri="sip:alice@example.com"
        )
        assert result.action == "answer"
        assert result.call.state == "answered"
        assert ("answer_local", "ivr") in harness.rtpengine.operations


class TestMediaTargetForms:
    """Media verbs accept a SIP object, a (call_id, from_tag) pair, or a bare
    call_id string — all resolving to the same recorded (call_id, from_tag)."""

    def test_play_media_target_forms_resolve_equivalently(self, harness):
        request = Request(method="INVITE", call_id="call-1", from_tag="ftag-1")
        asyncio.run(harness.rtpengine.play_media(request, file="/a.wav"))
        asyncio.run(harness.rtpengine.play_media(("call-1", "ftag-1"), file="/a.wav"))
        asyncio.run(harness.rtpengine.play_media("call-1", file="/a.wav"))

        calls = harness.rtpengine.media_calls
        assert calls[0]["call_id"] == "call-1" and calls[0]["from_tag"] == "ftag-1"
        assert calls[1]["call_id"] == "call-1" and calls[1]["from_tag"] == "ftag-1"
        # Bare string → best-effort, empty from_tag.
        assert calls[2]["call_id"] == "call-1" and calls[2]["from_tag"] == ""

    def test_echo_target_forms_resolve_equivalently(self, harness):
        request = Request(method="INVITE", call_id="call-9", from_tag="ftag-9")
        asyncio.run(harness.rtpengine.echo(request))
        asyncio.run(harness.rtpengine.echo(("call-9", "ftag-9")))
        asyncio.run(harness.rtpengine.echo("call-9"))

        calls = [c for c in harness.rtpengine.media_calls if c["op"] == "echo"]
        assert calls[0]["call_id"] == "call-9" and calls[0]["from_tag"] == "ftag-9"
        assert calls[1]["call_id"] == "call-9" and calls[1]["from_tag"] == "ftag-9"
        assert calls[2]["call_id"] == "call-9" and calls[2]["from_tag"] == ""

    def test_dtmf_from_on_dtmf_handler_shape(self, harness):
        # The @rtpengine.on_dtmf payload is (call_id, from_tag) strings; feeding
        # a bare call_id / pair straight into a media verb must work.
        asyncio.run(harness.rtpengine.play_dtmf(("call-7", "ftag-7"), "1"))
        call = harness.rtpengine.media_calls[-1]
        assert call["op"] == "play_dtmf"
        assert call["call_id"] == "call-7"
        assert call["from_tag"] == "ftag-7"
