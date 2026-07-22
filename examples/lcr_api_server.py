"""
Reference Least-Cost-Routing API for SIPhon — a runnable example of the LCR
JSON contract that examples/lcr_b2bua.py calls.

This is **illustrative**: a trivial in-memory longest-prefix table stands in for
a real rating engine. Swap `RATE_TABLE` / `decide()` for your BSS / rating
system (live rate decks, carrier quality, balance, margin). The request /
response shapes are the contract siphon speaks — kept in one typed place in
`siphon_sdk.lcr` (see docs/reference/lcr-api.md).

Run:
    pip install fastapi uvicorn siphon-sip
    uvicorn examples.lcr_api_server:app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

from fastapi import FastAPI

from siphon_sdk.lcr import LcrRequest, LcrReject, LcrResponse, Route

app = FastAPI(title="SIPhon LCR reference API")

# Longest-prefix → ordered carriers (cheapest first). Each route references a
# siphon `gateway:` group so siphon picks a healthy member and skips dead pools.
RATE_TABLE: dict[str, list[Route]] = {
    "+1": [
        # Cheapest first. carrier-a wants a tech-prefix in front of the number
        # and a per-INVITE account header; it also sends 404 for "no circuits",
        # so treat 404 as a reroute cause for this carrier.
        Route(carrier_id="carrier-a", gateway_group="carrier-a", rate=0.0042,
              currency="USD", billing_increment=60, timeout_secs=12,
              tech_prefix="1010288", number_policy="pstn-national@2026",
              headers={"X-Account": "42"},
              cdr_fields={"carrier_zone": "us-east", "rate_deck": "premium"},
              reroute_causes=[404, 408, 500, 502, 503, 504]),
        Route(carrier_id="carrier-b", gateway_group="carrier-b", rate=0.0051,
              currency="USD", billing_increment=60, timeout_secs=12),
    ],
    "+44": [
        Route(carrier_id="carrier-b", gateway_group="carrier-b", rate=0.0090,
              currency="USD", billing_increment=1, timeout_secs=12),
    ],
}


def decide(request: LcrRequest) -> LcrResponse:
    """Rate a query into an ordered decision (replace with your rating engine)."""
    number = request.dialed_number
    best: str | None = None
    for prefix in RATE_TABLE:
        if number.startswith(prefix) and (best is None or len(prefix) > len(best)):
            best = prefix
    if best is None:
        return LcrResponse(reject=LcrReject(code=404, reason="No Route"))
    # Return a fresh copy of the carrier list so the table isn't mutated.
    return LcrResponse(routes=list(RATE_TABLE[best]), cache_ttl_secs=300)


@app.post("/route")
async def route(payload: dict) -> dict:
    request = LcrRequest.from_dict(payload)
    return decide(request).to_dict()
