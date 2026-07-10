"""Tests for MockRtpEngine media-injection methods.

Covers play_media/stop_media/play_dtmf/silence+unsilence/block+unblock/echo —
the announcement, DTMF, and echo-test surface added for MMTEL / TAS-style scripts.
"""

from __future__ import annotations

import pytest

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
