# Number routing: LNP and redirect

Two routing jobs that hinge on an external data dip: **LNP** (local number
portability correction) and running SIPhon as a **redirect server**. SIPhon does
the SIP. The lookup, your ported-number database or your routing table, is the
business-logic part. In both recipes it is a small stub function you replace with
your real data source: an SQL query, an HTTP API, `cache.fetch`, or
`proxy.enum_lookup`.

!!! tip "Cost-based routing is built in"
    For carrier **least-cost routing** (cost-ordered failover across gateway
    pools, per-carrier CDRs, ring-timeout reroute), don't hand-roll a redirect.
    Use the built-in [LCR feature](least-cost-routing.md): your API owns the cost
    decision, SIPhon executes it. Same split, more machinery for free.

## LNP: correct the routing number

Dip your ported-number data, and if the number has ported, rewrite the R-URI
with the routing number (`rn`) and mark the dip as done (`npdi`) per
[RFC 4694](https://www.rfc-editor.org/rfc/rfc4694). `set_ruri` takes a full URI,
so the parameters land on the wire verbatim.

```python
from siphon import proxy, log

CARRIER_HOST = "carrier.example.net"

def lnp_dip(number: str) -> str | None:
    """Your dip: SS7/SOA query, HTTP API, or a local copy of the LNP database.
    Returns the LRN for a ported number, else None."""
    ...

@proxy.on_request("INVITE")
def route(request):
    called = request.ruri.user or ""

    lrn = lnp_dip(called)
    if lrn is not None:
        request.set_ruri(f"sip:{called};npdi;rn={lrn}@{CARRIER_HOST};user=phone")
        log.info(f"LNP {called} ported -> rn={lrn}")

    request.relay()
```

The wire result for a ported number:

```
INVITE sip:+15551234567;npdi;rn=+15559990000@carrier.example.net;user=phone SIP/2.0
```

## Redirect server (3xx)

A redirect server answers `3xx` with `Contact` headers and forwards nothing. The
caller retries the targets itself. Build the contact list from your lookup and
reply:

```python
from siphon import proxy

def routes_for(number: str) -> list[str]:
    """Your routing table. Returns target URIs, most-preferred first."""
    ...

@proxy.on_request("INVITE")
def redirect(request):
    routes = routes_for(request.ruri.user or "")
    if not routes:
        request.reply(404, "Not Found")
        return

    # One Contact per target. 302 for a single move, 300 for a choice.
    for uri in routes:
        request.add_reply_header("Contact", f"<{uri}>")
    request.reply(300 if len(routes) > 1 else 302, "Multiple Choices")
```

`add_reply_header` appends (so several `Contact` headers stack); `set_reply_header`
would replace. The transaction layer handles the ACK for your non-2xx response.

## Test it

```python
from siphon_sdk import mock_module
from siphon_sdk.request import Request

mock_module.install()

request = Request(method="INVITE", ruri="sip:+15551234567@example.net")
route(request)                                   # the LNP handler above
assert "rn=+15559990000" in str(request.ruri)
assert request.last_action.kind == "relay"
```

## The line

SIPhon rewrites the R-URI, stacks the `Contact` headers, and answers the
transaction correctly. Which number ported, and where a number should go, is
your data and your decision. That lookup is the part that's specific to your
business, so it stays in your hands (or a
[commercial engagement](../support.md) if you'd rather not run it yourself).

## See also

- Real script: [`examples/number_routing.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/number_routing.py) — both roles, with the stubs to replace.
- [Least-Cost Routing](least-cost-routing.md) for cost-ordered carrier failover.
- [Number normalization](number-normalization.md) to canonicalise E.164 before you route.
- [Request reference](../reference/request.md) — `set_ruri`, `add_reply_header`, `reply`.
