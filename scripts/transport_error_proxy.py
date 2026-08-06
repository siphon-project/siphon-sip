"""Test fixture proxy for the transport-error / transaction-timeout acceptance test.

Relays every out-of-dialog INVITE to a fixed next hop over TCP.  The test points
that next hop at a host which is up but has nothing listening on the SIP port, so
the pool's connect is refused immediately.

The script does nothing else on purpose: no `@proxy.on_failure`, no fork, no
retry.  The caller must still be answered, because RFC 3261 §16.9 makes a
transport error on forwarding equivalent to a 503 on that branch and §16.7 step 6
turns that into a 500 upstream.  Before that was wired, the branch simply went
quiet and the caller sat on its `100 Trying` until its own Timer F — 32 s.

Run by scripts/transport_error_test.sh via sipp/docker-compose.yaml
(`--profile transport-error`), config sipp/configs/siphon.transport-error-test.yaml.
"""
from siphon import proxy, log

# 172.20.0.98 is up (a plain sleeping container) but listens on nothing, so a
# TCP connect is refused at once rather than hanging until a connect timeout.
DEAD_NEXT_HOP = "sip:bob@172.20.0.98:5060;transport=tcp"


@proxy.on_request("INVITE")
def handle_invite(request):
    if request.in_dialog:
        request.loose_route()
        request.relay()
        return
    log.info(f"[transport-error] relaying to the dead next hop {DEAD_NEXT_HOP}")
    request.relay(DEAD_NEXT_HOP)


@proxy.on_request
def handle_other(request):
    if request.method == "INVITE":
        return
    if request.in_dialog:
        request.loose_route()
        request.relay()
        return
    request.reply(200, "OK")
