"""
SIPhon voice-AI, control-plane variant — the in-process half.

Same media path as voice_ai_b2bua.py: the call is answered by siphon and its audio
bridged to a WebSocket media server, with no B leg. The difference is *where the
policy lives*. Here the script does the minimum — identify the carrier, then hand
the call to an external application — and everything after that (how long to run,
when to transfer, when to hang up) is decided out of process.

`call.handover(..., answer=True, ws_uri=...)` is answer-first, sometimes called
AI-park: siphon answers the call and anchors its media to the WebSocket bridge
*before* handing over, so the controller inherits an already-connected channel
rather than having to answer it and then wire media. That commits the call —
CDR answer-time starts here, not in the controller.

Two things worth knowing before choosing this over the in-process example:

  * The audio never travels over the control plane. The AI reads and writes PCM on
    the WebSocket the media engine dialled; the control plane carries call
    control only. The two are independent connections to two different services.
  * Prompt playback and DTMF are not control-plane verbs yet, so an app that
    needs them still reads DTMF in-process via `@rtpengine.on_dtmf` (below) or
    handles it inside the AI over the audio stream.

Run:
    # 1. the AI side
    python3 siphon-rtp/examples/voice-ai/server.py     # ws://127.0.0.1:9001/stream
    # 2. the media engine
    siphon-rtp --control 127.0.0.1:8080
    # 3. the external controller
    IVR_APP_TOKEN=changeme-dev-token python3 examples/voice_ai_control_app.py
    # 4. siphon
    siphon -c examples/voice_ai_control.yaml
"""
from siphon import b2bua, proxy, rtpengine, log

APP = "voice-ai-app"


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def hand_to_controller(call):
    if not call.from_gateway("carriers"):
        log.warn(f"[{call.id}] INVITE from unknown source {call.source_ip}")
        call.reject(403, "Forbidden")
        return

    # Answer-first handover: siphon answers and bridges the audio to the AI, then
    # hands control out. `on_lost` decides what happens if the controller dies
    # mid-call — hang up rather than strand a caller on a bridge nobody owns.
    call.handover(
        APP,
        answer=True,
        profile="voice_ai",
        ws_uri="ws://127.0.0.1:9001/stream?call={call_id}",
        on_lost="hangup",
        deadline_ms=3000,
    )
    log.info(f"[{call.id}] answered and handed to {APP}")


@rtpengine.on_dtmf
def on_digit(call_id, from_tag, digit, duration_ms, volume):
    # DTMF is not a control-plane verb yet, so it surfaces here even though the
    # rest of the policy is out of process.
    log.info(f"[{call_id}] DTMF {digit} ({duration_ms}ms)")
