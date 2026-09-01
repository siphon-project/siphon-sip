"""Record-Routing relay for the siphon <-> third-party proxy interop stack.

Deliberately the smallest proxy that still exercises the thing under test: a
stateful, Record-Routing hop that forwards initial requests to a fixed next hop
and loose-routes everything in-dialog.

The point is not the routing logic — it is that the route set siphon *writes*
can be read back by a proxy that shares none of siphon's code, and that a route
set written by that proxy can be read back by siphon. An in-dialog BYE only
reaches the far end if both halves agree, so the SIPp scenarios need no header
assertions: the call either completes end to end or it does not.

The next hop comes from the environment so one script serves both chain
directions (siphon-in-front and siphon-behind).
"""
import os

from siphon import proxy

NEXT_HOP = os.environ["INTEROP_NEXT_HOP"]  # e.g. "sip:172.28.0.20:5060"


# One handler, not one per method. `@proxy.on_request` with no filter matches
# *every* method, and a filtered `@proxy.on_request("OPTIONS")` alongside it does
# not replace it — both run. Registering both meant the healthcheck OPTIONS was
# answered 200 locally *and* relayed to the next hop, which in the reverse chain
# is the SIPp UAS: it consumed its one scripted call on the healthcheck and was
# gone before the test INVITE arrived.
@proxy.on_request
def on_request(request):
    # Container healthcheck probe — answered locally, never relayed.
    if request.method == "OPTIONS" and not request.in_dialog:
        request.reply(200, "OK")
        return

    # In-dialog: follow the route set the two proxies built between them.
    #
    # loose_route() consumes only the Route entries that identify us (RFC 3261
    # §16.4); a False return means the top Route belongs to the other proxy and
    # relay() follows it (§16.6), so forward either way. Note it also returns
    # True when there is no Route at all, which is why the in-dialog test is
    # `request.in_dialog` and not the loose_route() return.
    if request.in_dialog:
        request.loose_route()
        request.relay()
        return

    # Initial request: stay in the path for the whole dialog, then forward.
    request.record_route()
    request.relay(NEXT_HOP)
