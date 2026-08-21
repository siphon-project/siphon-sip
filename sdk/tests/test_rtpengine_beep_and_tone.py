"""Tests for the 0.3.0 media surface: tone/HTTP play sources, overlay playback
with per-play gain, the ``ws_sample_rate`` / ``ws_vad_engine`` / beep-detection
per-call overrides, and the ``@rtpengine.on_beep`` hook.

The theme throughout is that the media engine *fails* an offer (or a play)
carrying a value it cannot honour rather than clamping it or falling back — so
every one of these is validated before it leaves siphon, and the tests assert
the refusal, not just the happy path.
"""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.testing import SipTestHarness


@pytest.fixture
def harness():
    h = SipTestHarness()
    h.reset()
    return h


class TestTonePlaySource:
    def test_preset_name_is_passed_through_verbatim(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, tone="ringback_eu")
    request.reply(180, "Ringing")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")

        assert ("play_media", "tone") in harness.rtpengine.operations
        call = harness.rtpengine.media_calls[-1]
        assert call["tone"] == "ringback_eu"
        assert call["overlay"] is False

    def test_cadence_spec_is_passed_through_verbatim(self, harness):
        # A cadence spec is told from a preset by the "/" — siphon keeps no copy
        # of the preset table, so both forms travel unchanged.
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.play_media(request, tone="425/1000,0/4000*inf")
    request.reply(180, "Ringing")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        assert harness.rtpengine.media_calls[-1]["tone"] == "425/1000,0/4000*inf"

    def test_empty_tone_is_rejected(self, harness):
        # Neither a preset name nor a cadence spec — the one thing that is wrong
        # under either reading, so it is caught before it reaches the engine.
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="tone="):
                loop.run_until_complete(
                    harness.rtpengine.play_media(("c", "f"), tone="   ")
                )
        finally:
            loop.close()


class TestHttpPlaySource:
    @pytest.mark.parametrize(
        "url",
        [
            "http://prompts.invalid/a.wav",
            "https://prompts.invalid/a.wav",
            "HTTPS://prompts.invalid/a.wav",
        ],
    )
    def test_http_and_https_accepted(self, harness, url):
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(harness.rtpengine.play_media(("c", "f"), url=url))
        finally:
            loop.close()

        assert ("play_media", "http") in harness.rtpengine.operations
        assert harness.rtpengine.media_calls[-1]["url"] == url

    @pytest.mark.parametrize(
        "url", ["file:///etc/passwd", "ftp://host/a.wav", "prompts/a.wav"]
    )
    def test_non_http_scheme_rejected(self, harness, url):
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="http://"):
                loop.run_until_complete(
                    harness.rtpengine.play_media(("c", "f"), url=url)
                )
        finally:
            loop.close()

    def test_exactly_one_source_still_enforced(self, harness):
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="exactly one"):
                loop.run_until_complete(
                    harness.rtpengine.play_media(
                        ("c", "f"),
                        tone="ringback_eu",
                        url="https://prompts.invalid/a.wav",
                    )
                )
        finally:
            loop.close()


class TestOverlayAndGain:
    def test_overlay_returns_play_id_and_marks_overlay(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    play_id = await rtpengine.play_overlay(
        request, file="/prompts/hold.wav", gain_decibels=-6
    )
    await rtpengine.set_play_gain(request, play_id, -18)
    await rtpengine.stop_media(request, play_id=play_id)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")

        ops = [op for op, _ in harness.rtpengine.operations]
        assert "play_overlay" in ops
        assert "set_play_gain" in ops

        overlay = next(
            c for c in harness.rtpengine.media_calls if c["op"] == "play_overlay"
        )
        assert overlay["overlay"] is True
        assert overlay["gain_decibels"] == -6

        gain = next(
            c for c in harness.rtpengine.media_calls if c["op"] == "set_play_gain"
        )
        assert gain["play_id"] == 1
        assert gain["gain_decibels"] == -18

        # The targeted stop must carry the handle, not stop everything.
        stop = next(c for c in harness.rtpengine.media_calls if c["op"] == "stop_media")
        assert stop["play_id"] == 1

    def test_untargeted_stop_carries_no_play_id(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.stop_media(request)
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")
        assert harness.rtpengine.media_calls[-1]["play_id"] is None

    def test_overlay_id_can_be_absent(self, harness):
        # An engine that accepted the overlay but assigned no handle: a script's
        # "can I duck this later" branch has to cope, so the mock can model it.
        harness.rtpengine.set_play_overlay_id(None)
        loop = asyncio.new_event_loop()
        try:
            play_id = loop.run_until_complete(
                harness.rtpengine.play_overlay(("c", "f"), tone="ringback_eu")
            )
        finally:
            loop.close()
        assert play_id is None


class TestMediaOverrides:
    def test_offer_records_per_call_overrides(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.offer(
        request,
        profile="voice_ai",
        beep_detection=True,
        beep_cadence_guard_ms=3000,
        ws_sample_rate=16000,
        ws_vad_engine="neural",
        ws_vad_min_speech_ms=80,
    )
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")

        operation, overrides = harness.rtpengine.media_overrides[-1]
        assert operation == "offer"
        assert overrides["beep_detection"] is True
        assert overrides["beep_cadence_guard_ms"] == 3000
        assert overrides["ws_sample_rate"] == 16000
        assert overrides["ws_vad_engine"] == "neural"
        assert overrides["ws_vad_min_speech_ms"] == 80

    def test_unset_overrides_leave_the_profile_alone(self, harness):
        harness.load_source(
            """
from siphon import proxy, rtpengine

@proxy.on_request
async def route(request):
    await rtpengine.offer(request, profile="voice_ai")
    request.reply(200, "OK")
"""
        )
        harness.send_request("INVITE", "sip:alice@example.com")

        _, overrides = harness.rtpengine.media_overrides[-1]
        assert all(value is None for value in overrides.values())

    @pytest.mark.parametrize("rate", [44100, 4000, 96000, 0])
    def test_bad_ws_sample_rate_rejected(self, harness, rate):
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="ws_sample_rate"):
                loop.run_until_complete(
                    harness.rtpengine.offer(None, ws_sample_rate=rate)
                )
        finally:
            loop.close()

    @pytest.mark.parametrize("rate", [8000, 16000, 24000, 48000])
    def test_boundary_ws_sample_rates_accepted(self, harness, rate):
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(harness.rtpengine.offer(None, ws_sample_rate=rate))
        finally:
            loop.close()
        assert harness.rtpengine.media_overrides[-1][1]["ws_sample_rate"] == rate

    def test_unknown_vad_engine_rejected(self, harness):
        # A closed selector: falling back to the detector the script was
        # explicitly avoiding is a silent downgrade, so it must raise.
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="ws_vad_engine"):
                loop.run_until_complete(
                    harness.rtpengine.offer(None, ws_vad_engine="telepathy")
                )
        finally:
            loop.close()

    def test_bad_tee_sample_rate_rejected_on_attach(self, harness):
        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="sample_rate"):
                loop.run_until_complete(
                    harness.rtpengine.attach_ws_tee(
                        ("c", "f"), "wss://asr.invalid/t", sample_rate=44100
                    )
                )
        finally:
            loop.close()

    def test_attach_ws_tee_records_sample_rate(self, harness):
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(
                harness.rtpengine.attach_ws_tee(
                    ("c", "f"), "wss://asr.invalid/t", sample_rate=16000
                )
            )
        finally:
            loop.close()
        assert harness.rtpengine.media_calls[-1]["sample_rate"] == 16000


class TestOnBeep:
    def test_bare_handler_is_a_catch_all(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

seen = []

@rtpengine.on_beep
def machine(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    log.info(f"beep {call_id} {frequency_hz} {offset_ms}")
"""
        )
        fired = harness.rtpengine.fire_beep("any-call", "any-tag")
        assert fired == 1

    def test_filters_scope_to_call_and_leg(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_beep
def any_beep(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    log.info("any")

@rtpengine.on_beep(call_id="abc", from_tag="callee-tag")
def specific(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    log.info("specific")
"""
        )
        # Catch-all only.
        assert harness.rtpengine.fire_beep("xyz", "other") == 1
        # Both.
        assert harness.rtpengine.fire_beep("abc", "callee-tag") == 2
        # Right call, wrong leg — the filter is per-leg because detection is
        # armed per leg.
        assert harness.rtpengine.fire_beep("abc", "caller-tag") == 1
        # Right leg, wrong call.
        assert harness.rtpengine.fire_beep("zzz", "callee-tag") == 1

    def test_handler_receives_the_full_payload(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_beep
def machine(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    log.info(f"{call_id}|{from_tag}|{to_tag}|{frequency_hz}|{duration_ms}|{offset_ms}")
"""
        )
        harness.rtpengine.fire_beep(
            "call-1",
            "callee-tag",
            to_tag="caller-tag",
            frequency_hz=1000.5,
            duration_ms=420,
            offset_ms=7300,
        )
        # offset_ms is the offset of the *tone*, so it must arrive unrounded and
        # unmodified — a consumer reasons about "how far into the leg" with it.
        assert (
            "call-1|callee-tag|caller-tag|1000.5|420|7300"
            in [message for _, message in harness.log.messages]
        )

    def test_clear_drops_registered_handlers(self, harness):
        harness.load_source(
            """
from siphon import rtpengine, log

@rtpengine.on_beep
def machine(call_id, from_tag, to_tag, frequency_hz, duration_ms, offset_ms):
    log.info("beep")
"""
        )
        assert harness.rtpengine.fire_beep("c", "f") == 1
        harness.rtpengine.clear()
        assert harness.rtpengine.fire_beep("c", "f") == 0
