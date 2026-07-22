"""
B2BUA + media anchoring + REFER terminate — anchored terminate-transfer test.

Anchors media through the media engine (rtpengine) on the initial call, then
accepts an in-dialog REFER in siphon-terminated mode. The dispatcher re-anchors
the surviving party to the transfer target on a fresh media session and tears
down the old anchor (the media-plane recipe under test). Runs against a REAL
rtpengine so the offer/answer/delete command sequence is exercised end to end.
"""
from siphon import b2bua, proxy, registrar, rtpengine, auth, log

DOMAIN = "siphon.test"
PROFILE = "rtp_passthrough"


@proxy.on_request("REGISTER")
def register(request):
    if not auth.require_www_digest(request, realm=DOMAIN):
        return
    registrar.save(request)


@b2bua.on_invite
async def new_call(call):
    contacts = registrar.lookup(call.ruri)
    if not contacts:
        call.reject(404, "Not Found")
        return
    # Anchor media (offer direction) before dialling the callee.
    await rtpengine.offer(call, profile=PROFILE)
    log.info(f"rtpengine offer done for call {call.call_id}")
    call.fork(contacts, strategy="parallel", timeout=30)


@b2bua.on_answer
async def answered(call, reply):
    log.info(f"Call {call.id} answered ({reply.status_code})")
    # Pass `call` so the answer reuses the A-leg Call-ID that matched the offer.
    await rtpengine.answer(reply, profile=PROFILE, call=call)
    log.info(f"rtpengine answer done for call {call.call_id}")


@b2bua.on_refer
def on_refer(call):
    log.info(f"Call {call.id} REFER -> {call.refer_to} (terminate)")
    call.accept_refer(mode="terminate")


@b2bua.on_bye
async def on_bye(call, initiator):
    log.info(f"B2BUA BYE: call {call.call_id}, initiator={initiator.side}")
    await rtpengine.delete(call)
