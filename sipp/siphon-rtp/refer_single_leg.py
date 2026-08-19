"""Functional-test script: answer a call single-leg, then cold-transfer it.

Drives the transfer off a call siphon answered itself — no B leg — which is the
shape a voice-AI call has. The transfer target is fixed and the trigger is a
short timer standing in for whatever would really decide (an AI, a DTMF digit,
an external controller).

Why a timer and not `call.refer()`: a call siphon answered itself never fires
`@b2bua.on_answer` (that hook is a B leg's 2xx arriving), and `call.refer()` is
deliberately a no-op from `@b2bua.on_invite` because the dialog is not confirmed
until the 2xx has gone out. So on a single-leg call the imperative
`b2bua.refer(call_id, target)` from an event context is the only path — the same
one the DTMF-triggered transfer in examples/voice_ai_b2bua.py takes.
"""
import os

from siphon import b2bua, proxy, rtpengine, timer, log

TRANSFER_TARGET = os.environ.get("TRANSFER_TARGET", "sip:agent@pbx.example.com")
# Long enough that the UAC has ACKed and is waiting, short enough to keep the
# scenario quick.
TRANSFER_DELAY_MS = int(os.environ.get("TRANSFER_DELAY_MS", "500"))
# Digest credentials for a trunk that challenges the in-dialog REFER.
TRANSFER_USER = os.environ.get("TRANSFER_USER", "siphon")
TRANSFER_PASSWORD = os.environ.get("TRANSFER_PASSWORD", "secret")


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def answer_then_transfer(call):
    answer_sdp = await rtpengine.answer_local(call, profile="voice_ai")
    if answer_sdp is None:
        log.warn(f"[{call.id}] no encodable codec — rejected 488")
        return

    # Credentials for the REFER retry if the peer challenges it. Set before the
    # transfer is scheduled: the retry reads them off the call.
    call.set_credentials(TRANSFER_USER, TRANSFER_PASSWORD)
    call.answer(200, "OK", body=answer_sdp, content_type="application/sdp")

    # The imperative verb keys on the SIP Call-ID, so carry it in the timer key.
    timer.set(f"transfer:{call.call_id}", TRANSFER_DELAY_MS, send_transfer)
    log.info(f"[{call.id}] answered; transfer scheduled in {TRANSFER_DELAY_MS}ms")


def send_transfer(key):
    sip_call_id = key.split(":", 1)[1]
    sent = b2bua.refer(sip_call_id, TRANSFER_TARGET)
    log.info(f"[{sip_call_id}] REFER to {TRANSFER_TARGET} sent={sent}")


@b2bua.on_bye
async def on_bye(call, initiator):
    log.info(f"[{call.id}] call ended by {initiator}")
