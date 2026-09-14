"""LCR route-sequence acceptance cases (sipp-b2bua-lcr).

The caller dials through siphon, the mock LCR API returns carrier A then
carrier B, and ``call.route()`` tries them in order: carrier A answers 503, a
reroute cause, so the sequence moves on to carrier B.

``@b2bua.on_failure`` decides nothing. A failure the sequence ends on is
therefore relayed to the caller as the carrier sent it, not rebuilt by siphon,
and that relayed response is what the caller scenario checks.
"""

from siphon import b2bua, lcr, log, proxy


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def route(call):
    decision = await lcr.route(call)
    if decision is None or not decision.routes:
        log.warn("LCR-NO-ROUTE")
        call.reject(503, "No Route")
        return
    if decision.reject:
        call.reject(decision.reject["code"], decision.reject["reason"])
        return
    call.route(decision.routes)


@b2bua.on_route_failure
def carrier_failed(call, route, code):
    # CI reads these lines: one per carrier that failed, in the order tried.
    log.info(f"LCR-CARRIER-FAILED {route.carrier_id} {code}")


@b2bua.on_failure
def failed(call, code, reason):
    # CI reads this line. Nothing is set on the call, so it ends with `code`.
    log.warn(f"LCR-FAILURE {code} {reason}")
