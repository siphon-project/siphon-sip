"""Minimal B2BUA LCR script for the SIPp failover test (scripts/lcr_sipp_test.sh).

on_invite asks the LCR API for carriers and hands them to call.route(), which
tries them cheapest-first with sequential failover. The first carrier rejects
(503, a reroute cause) so siphon fails over to the second, which answers.
"""
from siphon import b2bua, proxy, lcr, log


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def route(call):
    decision = await lcr.route(call)
    if decision is None or not decision.routes:
        call.reject(503, "No Route")
        return
    if decision.reject:
        call.reject(decision.reject["code"], decision.reject["reason"])
        return
    log.info(f"[{call.id}] LCR: {len(decision.routes)} carrier(s)")
    call.route(decision.routes)


@b2bua.on_route_failure
def carrier_failed(call, route, code):
    log.info(f"[{call.id}] carrier {route.carrier_id} failed {code}")


@b2bua.on_answer
def answered(call, reply):
    route = call.active_route
    if route:
        log.info(f"[{call.id}] answered via {route.carrier_id}")
    # The carriers burned on the way to that answer — nothing recorded these
    # before, so a completed call that failed over left no trace of it.
    for attempt in call.route_attempts:
        log.info(
            f"[{call.id}] burned {attempt['carrier_id']} "
            f"{attempt['status']} after {attempt['elapsed_ms']}ms"
        )


@b2bua.on_failure
def failed(call, code, reason):
    log.warn(f"[{call.id}] all carriers failed: {code} {reason}")
    call.reject(code, reason)


@b2bua.on_bye
def ended(call, initiator):
    call.terminate()
