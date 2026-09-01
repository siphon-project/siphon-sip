"""Proxy script for the lawful-intercept interop profile.

Anchors media on the native engine and relays to one fixed next hop.

Two things it deliberately does *not* do, both because they would dilute what
this profile is testing:

* **No registrar, no authentication.** A called party that has to REGISTER
  first turns a failure to intercept into a failure to route, and the two look
  identical in the delivery buffer. The next hop is configured, so the call
  either reaches the callee or it does not.
* **No interception logic.** There is nothing here about warrants, targets or
  X2, and that is the point: interception is enforced in the dispatcher, below
  the script, so a script cannot forget to intercept and cannot opt out. If
  this file could switch it off, the whole design would be wrong.

Media is anchored because content interception needs the engine in the path —
X3 delivers what the engine relayed.
"""

import os

from siphon import proxy, rtpengine, log

DOMAIN = "siphon.test"
PROFILE = "rtp_passthrough"
# Where the called party is. A literal, because nothing registers here.
NEXT_HOP = os.environ.get("LI_NEXT_HOP", "sip:172.29.0.40:5060")


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

    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return

    if request.method == "INVITE" and request.body:
        await rtpengine.offer(request, profile=PROFILE)
        log.info(f"media offer for INVITE call_id={request.call_id}")

    request.record_route()
    request.relay(NEXT_HOP)


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
