"""Drive a WebSocket takeover bridge through its whole lifecycle on a live call.

The point of the scenario is the **re-point**: moving a party from one media
server to another must be a second `attach_ws_bridge`, not a detach followed by
an attach. The detach would hand the media path back to the relay for as long as
it takes the next attach to land, and the party on the other end hears that gap.

SIPp cannot see the difference — every variant answers the call and hangs it up
the same way. The difference is the verb sequence on the control channel, which
the mock engine echoes, so that is what the job asserts:

    attach_ws_bridge, attach_ws_bridge, detach_ws_bridge

with no detach between the two attaches.
"""

from siphon import proxy, registrar, auth, rtpengine, log

DOMAIN = "siphon.test"
PROFILE = "rtp_passthrough"

FIRST_SERVER = "ws://172.20.0.116:9100/session-1"
SECOND_SERVER = "ws://172.20.0.116:9100/session-2"


@proxy.on_request
async def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    if request.in_dialog:
        if request.method == "BYE":
            await rtpengine.delete(request)
            log.info(f"media delete for BYE call_id={request.call_id}")
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

    request.record_route()
    request.fork([c.uri for c in contacts])


@proxy.on_reply
async def reply_route(request, reply):
    if 200 <= reply.status_code < 300 and reply.has_body("application/sdp"):
        await rtpengine.answer(reply, profile=PROFILE)

        # Take the call over: the WS server is now this leg's far side.
        await rtpengine.attach_ws_bridge(reply, FIRST_SERVER)
        log.info(f"bridge attached call_id={reply.call_id} -> {FIRST_SERVER}")

        # Hand the same party to a different session. One verb, no gap.
        await rtpengine.attach_ws_bridge(reply, SECOND_SERVER)
        log.info(f"bridge re-pointed call_id={reply.call_id} -> {SECOND_SERVER}")

        # Give the media path back to the relay.
        await rtpengine.detach_ws_bridge(reply)
        log.info(f"bridge detached call_id={reply.call_id}")

    reply.relay()


@proxy.on_cancel
async def cancel_route(request):
    await rtpengine.delete(request)
