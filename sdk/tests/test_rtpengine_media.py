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


class TestWebSocketBridge:
    """``ws_uri`` on offer / answer / answer_local — the voice-AI media bridge.

    The engine dials the URI and bridges the leg's RTP to it, so the URI is the
    whole feature: a script that cannot set it answers the call and bridges it
    nowhere.
    """

    def test_answer_local_records_ws_uri(self, harness):
        call = Call()
        asyncio.run(
            harness.rtpengine.answer_local(
                call, profile="voice_ai", ws_uri="wss://ai.example.com/stream"
            )
        )
        assert ("answer_local", "wss://ai.example.com/stream") in harness.rtpengine.ws_uris
        assert harness.rtpengine.media_calls[-1]["ws_uri"] == "wss://ai.example.com/stream"

    def test_no_bridge_requested_records_none(self, harness):
        asyncio.run(harness.rtpengine.answer_local(Call(), profile="voice_ai"))
        assert ("answer_local", None) in harness.rtpengine.ws_uris

    def test_call_id_placeholder_expands(self, harness):
        call = Call(call_id="abc123@example.invalid")
        asyncio.run(
            harness.rtpengine.offer(
                call, profile="voice_ai", ws_uri="wss://ai.example.com/{call_id}"
            )
        )
        assert harness.rtpengine.ws_uris[-1] == (
            "offer",
            "wss://ai.example.com/abc123@example.invalid",
        )

    def test_user_placeholders_expand_from_uris(self, harness):
        call = Call(
            call_id="c1",
            from_uri="sip:1001@example.com",
            to_uri="sip:2002@example.com",
        )
        asyncio.run(
            harness.rtpengine.offer(
                call,
                profile="voice_ai",
                ws_uri="wss://ai.example.com/s?from={from_user}&to={to_user}",
            )
        )
        assert harness.rtpengine.ws_uris[-1] == (
            "offer",
            "wss://ai.example.com/s?from=1001&to=2002",
        )

    def test_unknown_placeholder_raises(self, harness):
        with pytest.raises(ValueError, match="unknown placeholder"):
            asyncio.run(
                harness.rtpengine.offer(Call(call_id="c1"), ws_uri="wss://ai/{callid}")
            )

    def test_uri_without_placeholder_is_untouched(self, harness):
        asyncio.run(
            harness.rtpengine.offer(Call(call_id="c1"), ws_uri="wss://ai.example.com/stream")
        )
        assert harness.rtpengine.ws_uris[-1] == ("offer", "wss://ai.example.com/stream")

    def test_answer_reuses_the_uri_recorded_at_offer(self, harness):
        call = Call(call_id="c1")
        asyncio.run(
            harness.rtpengine.offer(call, profile="voice_ai", ws_uri="wss://ai/recorded")
        )
        asyncio.run(harness.rtpengine.answer_local(call))
        assert harness.rtpengine.ws_uris[-1] == ("answer_local", "wss://ai/recorded")

    def test_explicit_uri_overrides_the_recorded_one(self, harness):
        call = Call(call_id="c1")
        asyncio.run(
            harness.rtpengine.offer(call, profile="voice_ai", ws_uri="wss://ai/recorded")
        )
        asyncio.run(harness.rtpengine.answer_local(call, ws_uri="wss://ai/explicit"))
        assert harness.rtpengine.ws_uris[-1] == ("answer_local", "wss://ai/explicit")

    def test_driven_from_on_invite_handler(self, harness):
        harness.load_source(
            """
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def on_invite(call):
    sdp = await rtpengine.answer_local(
        call,
        profile="voice_ai",
        ws_uri=f"wss://ai.example.com/stream/{call.call_id}",
    )
    if sdp is not None:
        call.answer(200, "OK", body=sdp, content_type="application/sdp")
"""
        )
        result = harness.send_invite(
            ruri="sip:ai@example.com", from_uri="sip:alice@example.com"
        )
        assert result.action == "answer"
        assert result.call.state == "answered"
        operation, uri = harness.rtpengine.ws_uris[-1]
        assert operation == "answer_local"
        assert uri.startswith("wss://ai.example.com/stream/")


class TestWebSocketTee:
    """``attach_ws_tee`` / ``detach_ws_tee`` — the additive send-only stream.

    Distinct from ``ws_uri``, which is a *takeover*: with a tee the A-to-B
    relay stays wired and any SIPREC subscription keeps running, so this is
    the shape for live transcription / agent-assist on an ordinary call.
    """

    def test_attach_records_defaults(self, harness):
        call = Call(call_id="tee-1@example.invalid")
        asyncio.run(
            harness.rtpengine.attach_ws_tee(call, "wss://asr.example.com/s")
        )
        assert ("attach_ws_tee", "wss://asr.example.com/s") in harness.rtpengine.operations
        recorded = harness.rtpengine.media_calls[-1]
        assert recorded["op"] == "attach_ws_tee"
        assert recorded["call_id"] == "tee-1@example.invalid"
        assert recorded["ws_uri"] == "wss://asr.example.com/s"
        assert recorded["direction"] == "both"
        assert recorded["channels"] is None

    def test_attach_records_direction_and_channels(self, harness):
        asyncio.run(
            harness.rtpengine.attach_ws_tee(
                Call(), "wss://asr.example.com/s", direction="caller", channels=1
            )
        )
        recorded = harness.rtpengine.media_calls[-1]
        assert recorded["direction"] == "caller"
        assert recorded["channels"] == 1

    def test_attach_rejects_unknown_direction(self, harness):
        # "send" is the obvious wrong guess: a tee is send-only by definition,
        # so the axis the engine exposes is which leg(s), not which way.
        with pytest.raises(ValueError, match="direction"):
            asyncio.run(
                harness.rtpengine.attach_ws_tee(
                    Call(), "wss://asr.example.com/s", direction="send"
                )
            )

    def test_attach_rejects_bad_channel_count(self, harness):
        with pytest.raises(ValueError, match="channels"):
            asyncio.run(
                harness.rtpengine.attach_ws_tee(
                    Call(), "wss://asr.example.com/s", channels=3
                )
            )

    def test_detach_records_call(self, harness):
        call = Call(call_id="tee-2@example.invalid")
        asyncio.run(harness.rtpengine.detach_ws_tee(call))
        recorded = harness.rtpengine.media_calls[-1]
        assert recorded["op"] == "detach_ws_tee"
        assert recorded["call_id"] == "tee-2@example.invalid"

    def test_target_forms_resolve_equivalently(self, harness):
        # Same (call_id, from_tag) resolution as the other media verbs.
        asyncio.run(
            harness.rtpengine.attach_ws_tee(("call-5", "ftag-5"), "wss://h/s")
        )
        recorded = harness.rtpengine.media_calls[-1]
        assert recorded["call_id"] == "call-5"
        assert recorded["from_tag"] == "ftag-5"

    def test_tee_started_handler_receives_the_wire_shape(self, harness):
        # The wire shape is the payload's point: a consumer decodes the binary
        # frames from these values rather than guessing.
        seen = []

        @harness.rtpengine.on_ws_tee_started
        def tee_up(call_id, from_tag, stream_id, ws_uri, direction, channels, sample_rate):
            seen.append((call_id, from_tag, stream_id, ws_uri, direction, channels, sample_rate))

        fired = harness.rtpengine.fire_ws_tee_started(
            "c", "f", "s-1", "wss://asr.example.com/s",
            direction="caller", channels=1, sample_rate=16000,
        )
        assert fired == 1
        assert seen == [
            ("c", "f", "s-1", "wss://asr.example.com/s", "caller", 1, 16000)
        ]

    def test_tee_ended_handler_sees_an_unexpected_reason(self, harness):
        # The reason a handler exists: the server going away is otherwise
        # invisible — the call carries on and nothing reaches the consumer.
        dead = []

        @harness.rtpengine.on_ws_tee_ended
        def tee_down(call_id, from_tag, stream_id, reason, frames_sent, frames_dropped):
            if reason != "detached":
                dead.append((stream_id, reason, frames_sent, frames_dropped))

        harness.rtpengine.fire_ws_tee_ended("c", "f", "s-1", reason="detached")
        assert dead == []

        harness.rtpengine.fire_ws_tee_ended(
            "c", "f", "s-2", reason="transport_error",
            frames_sent=4200, frames_dropped=3,
        )
        assert dead == [("s-2", "transport_error", 4200, 3)]

    def test_tee_ended_handler_filters_by_call_id_and_from_tag(self, harness):
        hits = []

        @harness.rtpengine.on_ws_tee_ended(call_id="abc", from_tag="ftag1")
        def only_ours(call_id, from_tag, stream_id, reason, frames_sent, frames_dropped):
            hits.append(stream_id)

        assert harness.rtpengine.fire_ws_tee_ended("other", "ftag1", "s-1") == 0
        assert harness.rtpengine.fire_ws_tee_ended("abc", "wrong", "s-2") == 0
        assert harness.rtpengine.fire_ws_tee_ended("abc", "ftag1", "s-3") == 1
        assert hits == ["s-3"]

    def test_text_handler_receives_the_increment_with_its_loss_markers(self, harness):
        # U+FFFD is how a consumer sees where redundancy could not repair the
        # stream (RFC 4103 §5.3) — scrubbing it would hide the gap.
        seen = []

        @harness.rtpengine.on_text
        def transcript(call_id, from_tag, to_tag, text, direction):
            seen.append((call_id, from_tag, to_tag, text, direction))

        fired = harness.rtpengine.fire_text(
            "c", "f", "hel\ufffdo", to_tag="t", direction="a_to_b",
        )
        assert fired == 1
        assert seen == [("c", "f", "t", "hel\ufffdo", "a_to_b")]

    def test_text_handler_filters_on_call_id_and_from_tag(self, harness):
        hits = []

        @harness.rtpengine.on_text(call_id="abc", from_tag="ftag1")
        def transcript(call_id, from_tag, to_tag, text, direction):
            hits.append(text)

        assert harness.rtpengine.fire_text("other", "ftag1", "a") == 0
        assert harness.rtpengine.fire_text("abc", "wrong", "b") == 0
        assert harness.rtpengine.fire_text("abc", "ftag1", "c") == 1
        assert hits == ["c"]

    def test_clear_drops_registered_text_handlers(self, harness):
        @harness.rtpengine.on_text
        def transcript(*args):
            pass

        harness.rtpengine.clear()
        assert harness.rtpengine.fire_text("c", "f", "x") == 0

    def test_clear_drops_registered_tee_handlers(self, harness):
        @harness.rtpengine.on_ws_tee_started
        def tee_up(*args):
            pass

        @harness.rtpengine.on_ws_tee_ended
        def tee_down(*args):
            pass

        assert harness.rtpengine.fire_ws_tee_started("c", "f", "s", "ws://h/s") == 1
        assert harness.rtpengine.fire_ws_tee_ended("c", "f", "s") == 1
        harness.rtpengine.clear()
        assert harness.rtpengine.fire_ws_tee_started("c", "f", "s", "ws://h/s") == 0
        assert harness.rtpengine.fire_ws_tee_ended("c", "f", "s") == 0
