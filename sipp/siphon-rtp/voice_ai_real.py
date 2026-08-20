"""Voice-AI single-leg answer, aimed at a containerised WebSocket AI server.

A trimmed copy of examples/voice_ai_b2bua.py for the real-engine functional
test. It exists for one reason: the example hardcodes
`ws://127.0.0.1:9001/stream`, which is correct for the single-host run-book in
its docstring but wrong here — under compose the engine and the AI server are
separate containers, so the engine's loopback is not the AI server.

Everything else is deliberately the same shape as the example, because the
point of the test is that the documented pattern works against the real engine.
The DTMF transfer arm is dropped: this scenario never sends DTMF, and a handler
that is never invoked would be dead weight in a test fixture.
"""
import os

from siphon import b2bua, proxy, rtpengine, log

# The AI server's address on the compose network. Env-driven rather than
# hardcoded so the compose file stays the single place IPs are assigned.
AI_WS_URI = os.environ.get("AI_WS_URI", "ws://172.20.0.131:9001/stream?call={call_id}")


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def answer_with_ai(call):
    if not call.from_gateway("carriers"):
        log.warn(f"[{call.id}] INVITE from unknown source {call.source_ip}")
        call.reject(403, "Forbidden")
        return

    # Single-leg answer: the engine picks one encodable codec from the caller's
    # offer, synthesises the RFC 3264 answer, and dials the WebSocket bridge.
    # With the real engine a failed WS dial fails this call outright (the engine
    # tears the call down and returns an error rather than answering into a
    # bridge that is not up), so reaching call.answer() below already means the
    # socket is connected. Whether audio actually crosses it is what the AI
    # server asserts on the other side.
    answer_sdp = await rtpengine.answer_local(
        call,
        profile="voice_ai",
        ws_uri=AI_WS_URI,
    )
    if answer_sdp is None:
        log.warn(f"[{call.id}] no encodable codec in offer — rejected 488")
        return

    call.answer(200, "OK", body=answer_sdp, content_type="application/sdp")
    log.info(f"[{call.id}] answered; audio bridged to the AI at {AI_WS_URI}")


@b2bua.on_bye
async def on_bye(call, initiator):
    log.info(f"[{call.id}] call ended by {initiator}")
