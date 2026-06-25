"""Test fixture proxy script for the reply.reject() acceptance scenario.

Routes every out-of-dialog INVITE to a fixed downstream UAS, then on the UAS's
183 Session Progress (early media) rejects the in-progress INVITE with 503 via
reply.reject() — the IMS P-CSCF media-authorization-failure shape (N5/Rx auth
runs at answer time in @proxy.on_reply; a failure must reject the leg + CANCEL
downstream rather than proceed medialess).

Used by sipp/reject_uac.xml + sipp/reject_uas.xml (see those headers for the
native run commands).
"""
from siphon import proxy, log

UAS_NEXT_HOP = "sip:bob@127.0.0.2:5061"


@proxy.on_request
def route(request):
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(481, "Call/Transaction Does Not Exist")
        return
    if request.method == "INVITE":
        request.relay(UAS_NEXT_HOP)
        return
    request.reply(200, "OK")


@proxy.on_reply
def on_reply(request, reply):
    # Media authorization runs at answer time. On the 183's SDP a failure
    # rejects the in-progress INVITE: 503 upstream to the caller + CANCEL to the
    # downstream UAS. reject() returns True on a provisional (clean), False on a
    # final (a proxy cannot retract a 2xx — then proceed best-effort).
    if request.method == "INVITE" and reply.status_code == 183:
        if reply.reject(503, "Media Authorization Failed"):
            log.info("[reject-test] 183 -> reply.reject(503): 503 upstream + CANCEL downstream")
            return
        log.warn("[reject-test] reject returned False (already final) — relaying")
    reply.relay()
