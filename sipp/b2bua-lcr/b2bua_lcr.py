"""LCR route-sequence acceptance cases (sipp-b2bua-lcr).

The caller dials through siphon and ``call.route()`` tries the carriers the mock
LCR API returns, in order. The mock picks the carriers by the called number, and
so does the ring bound below:

- +15550100002 (routes.json): carrier A answers 503, a reroute cause, so the
  sequence moves on to carrier B, whose 183 and then 404 end the call.
- +15550100003 (routes.15550100003.json): the ringing carrier answers 183 and
  holds, past its 3 s ``timeout_secs``, until the 8 s ring bound; the untried
  carrier after it must never be dialled.

``@b2bua.on_failure`` decides nothing. A failure the sequence ends on is
therefore relayed to the caller as the carrier sent it, or as siphon's own 408
when the ring runs out, and that response is what the caller scenario checks.
"""

from siphon import b2bua, lcr, log, proxy

# call.route(timeout=...) by called number: how long a carrier that has shown
# progress may keep the call. Any other number gets call.route()'s own default.
RING_BOUND_SECS = {"+15550100003": 8}
DEFAULT_RING_BOUND_SECS = 30


def called_number(call):
    """The user part of the call's Request-URI, or None when it has none."""
    request_uri = call.ruri
    return request_uri.user if request_uri is not None else None


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
    ring_bound = RING_BOUND_SECS.get(called_number(call), DEFAULT_RING_BOUND_SECS)
    call.route(decision.routes, timeout=ring_bound)


@b2bua.on_route_failure
def carrier_failed(call, route, code):
    # CI reads these lines: one per carrier that failed, in the order tried.
    log.info(f"LCR-CARRIER-FAILED {route.carrier_id} {code}")


@b2bua.on_failure
def failed(call, code, reason):
    # CI reads this line. Nothing is set on the call, so it ends with `code`.
    log.warn(f"LCR-FAILURE {code} {reason}")
