"""SIPhon B2BUA script for the `Replaces` takeover at an SRTP edge (fixture).

The caller speaks SRTP, the callee plain RTP, and every call is anchored with
a direction-bound profile whose two halves say so. The takeover INVITE reaches
`on_invite` like any other call, so the script offers it to the media engine
and dials before siphon performs the handover instead. That first offer is
part of what the test measures: the takeover has to build on the session the
script already opened, not open a second one beside it.
"""
import os

from siphon import b2bua, log, proxy, rtpengine

CALLEE = os.environ.get("REPLACES_CALLEE", "sip:bob@172.20.0.154:6002")
PROFILE = "srtp_edge"


@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local:
        request.reply(200, "OK")


@b2bua.on_invite
async def new_call(call):
    await rtpengine.offer(call, profile=PROFILE)
    call.dial(CALLEE, timeout=30)


@b2bua.on_answer
async def answered(call, reply):
    await rtpengine.answer(reply, call=call)
    log.info(f"[{call.id}] answered ({reply.status_code})")


@b2bua.on_bye
async def ended(call, initiator):
    log.info(f"[{call.id}] BYE (initiator: {initiator.side})")
    await rtpengine.delete(call)
