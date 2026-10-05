"""
B2BUA at an SRTP edge: the caller speaks SRTP, the callee plain RTP.

The call is anchored with a direction-bound profile, one whose two halves
describe different sides. The scenarios then have the callee put the call on
hold and take it off again, and each party checks that what it is sent stays in
its own transport whoever re-offers.
"""
from siphon import b2bua, rtpengine, log

PROFILE = "srtp_edge"
CALLEE = "sip:bob@172.20.0.224:5060"


@b2bua.on_invite
async def new_call(call):
    await rtpengine.offer(call, profile=PROFILE)
    call.dial(CALLEE, timeout=30)


@b2bua.on_answer
async def answered(call, reply):
    await rtpengine.answer(reply, profile=PROFILE, call=call)
    log.info(f"anchored call {call.call_id}")


@b2bua.on_bye
async def on_bye(call, initiator):
    await rtpengine.delete(call)
