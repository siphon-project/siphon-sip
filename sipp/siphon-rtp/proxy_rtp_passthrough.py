"""Proxy media anchoring for the real-engine tests, on a plain RTP relay.

A copy of examples/proxy_rtpengine.py with one deliberate change: the profile is
`rtp_passthrough` rather than `srtp_to_rtp`.

Why it matters. `srtp_to_rtp` is for an SRTP offerer calling a plain-RTP
answerer: its answer half asks for `RTP/SAVP` toward the offerer. The SIPp UAC
(sipp/rtpengine_uac.xml) offers plain `RTP/AVP` with no crypto, so the profile
describes an SRTP interworking this scenario does not perform. An SDES answer
toward that offerer would have no crypto attribute to accept (RFC 4568 §5.1.2):
the offer carries none.

The control-plane mock never noticed, because it echoes SDP back without
negotiating anything. That is the difference this whole test exists to expose,
so the fix is to stop asking for an SRTP interworking the scenario does not
perform, not to relax the engine. Both legs here are plain RTP, so
`rtp_passthrough` is what the flow actually is.

Testing the real SRTP interworking path needs a UAC that offers SAVP with a
crypto line (or, for `rtp_to_srtp`, a UAS that answers with one); that is a
separate scenario, not this one.
"""

import os
from siphon import proxy, registrar, auth, rtpengine, log

DOMAIN = "siphon.test"
# The two control-plane A/B jobs (siphon-rtp-native / siphon-rtp-ng) override
# this to a codec-restricted profile so both planes are asserted to apply the
# same codec policy. Everything else keeps the plain relay.
PROFILE = os.environ.get("MEDIA_PROFILE", "rtp_passthrough")


@proxy.on_request
async def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    if request.in_dialog:
        if request.method == "BYE":
            await rtpengine.delete(request)
            log.info(f"media delete for BYE call_id={request.call_id}")
        elif request.method == "INVITE" and request.body:
            await rtpengine.offer(request, profile=PROFILE)
            log.info(f"media offer for re-INVITE call_id={request.call_id}")

        request.loose_route()
        request.relay()
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return

    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    if request.method == "INVITE" and request.body:
        await rtpengine.offer(request, profile=PROFILE)
        log.info(f"media offer for INVITE call_id={request.call_id}")

    request.record_route()
    request.fork([c.uri for c in contacts])


@proxy.on_reply
async def reply_route(request, reply):
    if 200 <= reply.status_code < 300 and reply.has_body("application/sdp"):
        await rtpengine.answer(reply, profile=PROFILE)
        log.info(f"media answer for reply call_id={reply.call_id}")

    reply.relay()


@proxy.on_cancel
async def cancel_route(request):
    await rtpengine.delete(request)
    log.info(f"media delete for CANCEL call_id={request.call_id}")
