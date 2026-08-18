"""
SIPhon voice-AI B2BUA — a carrier call answered by an AI over a WebSocket.

siphon answers the carrier's INVITE itself as a UAS. There is no B leg: the media
engine anchors the call as a *single-leg* session and bridges the caller's audio to
an external WebSocket media server, which becomes the far side. The engine decodes
RTP to linear PCM and streams it up; PCM the server sends back is encoded to RTP
toward the caller. The AI never touches RTP, jitter buffers or codecs.

All policy is in this file — nothing external drives the call. For the same media
path with policy in an *external* application instead, see voice_ai_control.py.

The shape:

  1. identify the carrier by source IP against a gateway group,
  2. `rtpengine.answer_local(...)` — the engine synthesises an RFC 3264 answer for
     the caller's own offer and dials the WebSocket bridge,
  3. answer the call with that SDP,
  4. surface DTMF and bridge failures to the script.

Requires `media.backend: siphon-rtp` — the bridge is a native engine extension.
rtpengine and rtpproxy have no equivalent and fail the config load.

Run:
    # 1. the AI side (siphon-rtp's reference echo server, or your own agent)
    python3 siphon-rtp/examples/voice-ai/server.py     # ws://127.0.0.1:9001/stream
    # 2. the media engine
    siphon-rtp --control 127.0.0.1:8080
    # 3. siphon
    siphon -c examples/voice_ai_b2bua.yaml

See docs/cookbook/voice-ai.md for the full run-book.
"""
from siphon import b2bua, proxy, rtpengine, log


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def answer_with_ai(call):
    # Source-IP membership of the carrier pool. On UDP this is a direction hint
    # only (spoofable); the trunk is TLS/TCP in production, where the handshake
    # makes it a real trust signal.
    if not call.from_gateway("carriers"):
        log.warn(f"[{call.id}] INVITE from unknown source {call.source_ip}")
        call.reject(403, "Forbidden")
        return

    # Single-leg answer: the engine picks one encodable codec from the caller's
    # offer and returns the answer SDP. `ws_uri` makes the WebSocket server this
    # leg's far side rather than a SIP peer — {call_id} expands per call, so the
    # AI can correlate the stream with the call without a side channel.
    #
    # Returns None when the offer carried no codec this engine build can encode:
    # auto_reject has already set a deferred 488 (RFC 3261 §13.3.1.2) on the call,
    # so there is nothing left to answer.
    answer_sdp = await rtpengine.answer_local(
        call,
        profile="voice_ai",
        ws_uri="ws://127.0.0.1:9001/stream?call={call_id}",
    )
    if answer_sdp is None:
        log.warn(f"[{call.id}] no encodable codec in offer — rejected 488")
        return

    call.answer(200, "OK", body=answer_sdp, content_type="application/sdp")
    log.info(f"[{call.id}] answered; audio bridged to the AI")


@b2bua.on_bye
async def on_bye(call, initiator):
    # The engine tears the bridge down with the call, so there is no media
    # cleanup to do here. Release whatever per-call state the AI side holds.
    log.info(f"[{call.id}] call ended by {initiator}")


@rtpengine.on_dtmf
def on_digit(call_id, from_tag, digit, duration_ms, volume):
    # In-band / RFC 4733 DTMF the engine detected, surfaced as a script event.
    # An IVR would accumulate these; the AI usually just wants the digit.
    log.info(f"[{call_id}] DTMF {digit} ({duration_ms}ms)")


@rtpengine.on_ws_tee_ended
def on_tee_ended(call_id, from_tag, stream_id, reason, frames_sent, frames_dropped):
    # Only fires if this script also attaches a tee (it does not by default) —
    # kept here because a tee dying is otherwise invisible: the call carries on
    # and the consumer simply stops receiving audio. See docs/media-engines.md.
    if reason != "detached":
        log.warn(f"[{call_id}] tee {stream_id} died: {reason}")


# Handing the caller off to a human is a REFER on the A dialog —
# call.refer("sip:agent@pbx.example.com"). Not wired here: this example is the
# answer-and-stream path, and a carrier that challenges an in-dialog REFER needs
# credentials on the retry, which is a separate concern from the media bridge.
