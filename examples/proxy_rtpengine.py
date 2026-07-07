"""
SIPhon proxy script with media anchoring.

Used for functional testing: anchors media through the media engine
on INVITE (offer) and reply (answer), deletes on BYE.

The `rtpengine` namespace is backend-agnostic: this script runs unchanged
on either media engine — flip `media.backend` between `rtpengine` (default)
and `siphon-rtp` in siphon.yaml. See docs/media-engines.md.
"""
from siphon import proxy, registrar, auth, rtpengine, log

DOMAIN = "siphon.test"


@proxy.on_request
async def route(request):
    # Local OPTIONS ping
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # In-dialog sequential requests
    if request.in_dialog:
        if request.method == "BYE":
            await rtpengine.delete(request)
            log.info(f"RTPEngine delete for BYE call_id={request.call_id}")
        elif request.method == "INVITE" and request.body:
            # Re-INVITE: renegotiate media (hold/resume/codec change)
            await rtpengine.offer(request, profile="srtp_to_rtp")
            log.info(f"RTPEngine offer for re-INVITE call_id={request.call_id}")

        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
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

    # For INVITE with SDP, anchor media through RTPEngine (offer)
    if request.method == "INVITE" and request.body:
        await rtpengine.offer(request, profile="srtp_to_rtp")
        log.info(f"RTPEngine offer for INVITE call_id={request.call_id}")

    request.record_route()
    request.fork([c.uri for c in contacts])


@proxy.on_reply
async def reply_route(request, reply):
    # For 200 OK to INVITE with SDP, anchor media through RTPEngine (answer)
    if reply.status_code >= 200 and reply.status_code < 300:
        if reply.has_body("application/sdp"):
            await rtpengine.answer(reply, profile="srtp_to_rtp")
            log.info(f"RTPEngine answer for reply call_id={reply.call_id}")

    reply.relay()


@proxy.on_cancel
async def cancel_route(request):
    # The INVITE was CANCELled before any final response. on_reply/on_failure
    # never fire for a cancel — the proxy answers 487 at the transaction layer
    # and the session is gone — so without this hook the media anchored on the
    # INVITE offer above would linger until RTPEngine's own inactivity timeout.
    await rtpengine.delete(request)
    log.info(f"RTPEngine delete for CANCEL call_id={request.call_id}")
