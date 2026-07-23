"""
SIPhon B2BUA Least-Cost Routing (LCR).

The routing *decision* (which carrier, in what order, at what cost) is owned by
an external HTTP JSON API — siphon is not a rating engine. This B2BUA:

  1. normalizes the dialed number to +E.164,
  2. asks the LCR API for an ordered carrier decision (cached),
  3. hands the routes to `call.route(...)`, which tries them cheapest-first with
     sequential failover — each carrier a fresh B-leg dialog (new Call-ID), so
     no carrier ever sees a reused Call-ID (the proxy serial-fork footgun),
  4. on answer, stamps the winning carrier + rate onto a CDR.

LCR is **B2BUA-only** — see docs/cookbook/least-cost-routing.md for why. A
reference LCR API (FastAPI) that implements the contract lives in
examples/lcr_api_server.py.

Run: siphon -c examples/lcr_b2bua.yaml
"""
from siphon import b2bua, proxy, gateway, cdr, lcr, log


@proxy.on_request("OPTIONS")
def health(request):
    request.reply(200, "OK")


@b2bua.on_invite
async def route(call):
    # Ingress: canonicalize the dialed number so the API rates a consistent
    # +E.164 (and CDRs are consistent). Applies to all carriers.
    call.rewrite_identities("ims-e164@2026")

    # Tag the ingress trunk from gateway membership (source-IP match) so the API
    # can apply a per-customer rate deck; it's also part of the decision cache key.
    trunk_group = "cust-trunks" if call.from_gateway("cust-trunks") else None

    decision = await lcr.route(call, trunk_group=trunk_group)
    if decision is None:
        # API unreachable and no fallback_gateway_group configured.
        log.error(f"[{call.id}] LCR API unavailable")
        call.reject(503, "Route Unavailable")
        return
    if decision.reject:
        # API-side block (no route / balance / fraud).
        call.reject(decision.reject["code"], decision.reject["reason"])
        return
    if not decision.routes:
        call.reject(404, "No Route")
        return

    log.info(f"[{call.id}] LCR: {len(decision.routes)} carrier(s), "
             f"cheapest={decision.routes[0].carrier_id}")
    # Routing policy stays in Python — the script may filter/reorder here
    # (e.g. drop carriers over a rate ceiling) before executing.
    call.route(decision.routes)


@b2bua.on_answer
def answered(call, reply):
    route = call.active_route          # the carrier that won the failover
    if route:
        log.info(f"[{call.id}] answered via {route.carrier_id} "
                 f"(rate={route.rate})")
        # CDR fields must be strings.
        extra = {"carrier_id": route.carrier_id, "route_source": "lcr"}
        if route.rate is not None:
            extra["rate"] = f"{route.rate:.5f}"
        if route.currency:
            extra["currency"] = route.currency
        cdr.write(call, extra=extra)


@b2bua.on_failure
def failed(call, code, reason):
    # Fires only once every carrier in the list has been tried (the list was
    # exhausted). `code`/`reason` are the last carrier's final response.
    log.warn(f"[{call.id}] all carriers failed: {code} {reason}")
    call.reject(code, reason)


@b2bua.on_bye
def ended(call, initiator):
    log.info(f"[{call.id}] BYE (initiator: {initiator.side})")
    call.terminate()
