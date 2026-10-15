"""Fixture for scripts/proxy_release_test.sh: a Record-Routing proxy that ends
an answered call itself, with ``proxy.release``, once the caller sends an
in-dialog INFO. The INFO stands in for what tells a P-CSCF the bearer is gone
(an Rx ASR, a media timeout): something outside the dialog's own transactions.
"""

from siphon import log, proxy, timer

CALLEE = "sip:bob@172.20.0.68:5060"
REASON = 'SIP;cause=503;text="Bearer released"'


@proxy.on_request
def route(request):
    if request.in_dialog:
        if request.method == "INFO":
            request.reply(200, "OK")
            # Released from a timer, the way an out-of-band trigger reaches it:
            # no transaction of the dialog is open when it runs.
            timer.set(f"release:{request.call_id}", 200, release)
            return
        request.loose_route()
        request.relay()
        return
    if request.method == "INVITE":
        request.record_route()
        request.relay(CALLEE)
        return
    request.reply(405, "Method Not Allowed")


async def release(key):
    call_id = key.split(":", 1)[1]
    released = await proxy.release(call_id, reason=REASON)
    log.info(f"proxy.release({call_id}) -> {released}")
