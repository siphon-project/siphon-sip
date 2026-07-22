# Least-Cost Routing (LCR)

Route outbound calls across carriers by cost, with an external API making the
decision and siphon executing it against its gateway health/failover machinery.

siphon is **not a rating engine**. The decision — which carrier, in what order,
at what cost — is owned by an external HTTP JSON API you run (rate decks, prefix
match, quality, margin, balance). siphon asks that API, caches the answer, and
executes the ordered route set: it resolves each carrier's gateway pool to a
healthy member, tries them cheapest-first with sequential failover, and stamps
the winning carrier onto the CDR.

> The split: **API owns cost order** (cached). **siphon owns liveness + execution**
> (healthy-member selection, dead-carrier skip, sequential failover, per-call CDR).

## Why B2BUA-only (not proxy)

LCR in siphon is exposed **only** on the B2BUA (`call.route(...)`). There is no
proxy LCR path, on purpose. The decisive reason is **dialog hygiene**.

A proxy doing serial LCR is transparent end-to-end, so it keeps the **same
Call-ID** toward every carrier it tries. That is the classic Kamailio
serial-fork footgun:

- **Ghost dialogs / double-connect.** If carrier A actually set up state before
  you failed over (a 200 racing your CANCEL, a half-answer), carrier B now sees
  the *same* Call-ID. Some carriers reject it as a duplicate; worse, you can be
  billed on two carriers for one call.
- **CDRs you can't separate.** Every attempt shares one Call-ID, so "attempt to
  A (failed) / attempt to B (answered)" can't be told apart per carrier for
  ASR / billing.
- **No mid-call control.** In-dialog re-INVITE / BYE follow the established
  route set; the proxy isn't in the dialog, so it can't reroute or tear down on
  credit.

A B2BUA mints a **fresh B-leg dialog — new Call-ID / From-tag / CSeq — per
carrier attempt**. Carriers never collide, per-carrier CDRs separate cleanly,
and the B2BUA owns both dialogs (retry, per-carrier media, credit teardown). The
customer-facing A-leg Call-ID stays stable regardless of which carrier wins.

B2BUA is also required for online charging (mid-call credit teardown) and
per-carrier media/codec handling.

## The flow

```python
from siphon import b2bua, cdr, lcr, log

@b2bua.on_invite
async def route(call):
    call.rewrite_identities("ims-e164@2026")        # normalize the dialed number
    decision = await lcr.route(call, trunk_group="cust-trunks")
    if decision is None:                            # API down, no fallback
        call.reject(503, "Route Unavailable")
        return
    if decision.reject:                             # API-side block
        call.reject(decision.reject["code"], decision.reject["reason"])
        return
    if not decision.routes:
        call.reject(404, "No Route")
        return
    call.route(decision.routes)                     # sequential failover

@b2bua.on_answer
def answered(call, reply):
    route = call.active_route                        # the carrier that won
    if route:
        cdr.write(call, extra={"carrier_id": route.carrier_id,
                               "rate": f"{route.rate:.5f}",
                               "route_source": "lcr"})

@b2bua.on_failure
def failed(call, code, reason):                      # only after all carriers tried
    call.reject(code, reason)
```

`decision.routes` is an ordered `list[Route]` — routing *policy* stays in Python,
so the script may filter or reorder (drop carriers over a rate ceiling, prefer a
region) before `call.route(...)`. siphon resolves and dials from there.

Full example: [`examples/lcr_b2bua.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/lcr_b2bua.py)
+ `.yaml`. Reference API (FastAPI): [`examples/lcr_api_server.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/lcr_api_server.py).

## Sequential failover

`call.route([...])` tries carriers **one at a time, in order**:

- Dials the first routable carrier and arms its ring timeout (`timeout_secs`,
  else `call.route(timeout=…)`, else 30s).
- On a carrier **reject** (4xx/5xx) or **ring-timeout**, advances to the next
  carrier — a **fresh B-leg dialog** each time.
- A `6xx` from a carrier stops the sequence (global rejection, RFC 3261 §16.7
  spirit).
- The A-leg receives a failure only once **every** carrier is exhausted;
  `@b2bua.on_failure` fires once, with the last carrier's response.
- On answer, `call.active_route` is the carrier that won.

`call.fork(strategy="sequential")` uses the same engine for a bare target list
(this now actually fails over — previously the strategy was ignored). Captured
inbound flows (WebSocket connection reuse) are not carried on the sequential
path; use `strategy="parallel"` for WebSocket callees.

## Gateway integration

A route names a **`gateway_group`** (a `gateway:` carrier pool). At dial time
siphon picks a healthy member (weighted/round-robin/hash per the group), and
**skips the carrier entirely if the pool is down** — health-probing you already
configured, no round-trip to the LCR API. A route may instead pin an explicit
`next_hop`, or override the whole Request-URI with `ruri`.

## Per-carrier shaping (prefix, headers)

Carriers want the number in different shapes:

- **`tech_prefix`** — a dial/tech-prefix prepended to the R-URI userpart
  (`"1010288"`, `"#31#"`). Many carriers route or bill on a prefix in front of
  the E.164 number. siphon prepends it per carrier, so `+12025550123` becomes
  `1010288+12025550123` toward that carrier only.
- **`ruri`** — full Request-URI override when a carrier wants a specific number
  format or its own host.
- **`headers`** — per-carrier headers injected on the B-leg INVITE (an account
  token, a routing tag), applied after the header policy so they always land.

```json
{ "carrier_id": "carrier-a", "gateway_group": "carrier-a",
  "tech_prefix": "1010288", "headers": { "X-Account": "42" }, "rate": 0.0042 }
```

## Reroute causes (some carriers don't play nice)

Failover only happens on a **reroute cause** — a SIP code that means "this
carrier failed, try another", not "the call is over". A `486 Busy` or `603
Decline` is forwarded to the caller as-is (trying another carrier won't help); a
`503`/`408` fails over.

The default reroute set is `[408, 500, 502, 503, 504]`. Override it at three
levels (most specific wins):

- **Generic** — `lcr.reroute_causes` in `siphon.yaml`.
- **Per-gateway** — `gateway.groups[].reroute_causes`, for a carrier that sends
  non-standard codes (e.g. `404`/`403` for "no circuits").
- **Per-route** — the API's `reroute_causes` on a `Route`, when the API knows a
  specific carrier misbehaves.

```yaml
lcr:
  reroute_causes: [408, 500, 502, 503, 504]   # generic (this is also the default)

gateway:
  groups:
    - name: "carrier-x"
      reroute_causes: [404, 408, 500, 503]     # carrier-x sends 404 for no-circuits
      destinations: [ ... ]
```

## Caching and fallback

The LCR API is on the call-setup path, so:

- **Decisions are cached** in a named cache (`lcr.cache`), keyed by
  `trunk_group:dialed_number`, for the API-provided `cache_ttl_secs` (or the
  configured default). With a Redis-backed cache, a decision cached on one node
  is reused fleet-wide. A `cache_ttl_secs` of `0`/absent means don't cache.
- **A static fallback** (`lcr.fallback_gateway_group`) is used when the API is
  unreachable or times out, so routing degrades instead of every call failing.
  Without a fallback, an API failure surfaces to the script as `None` (answer a
  5xx).

## Config

```yaml
lcr:
  api_url: "${LCR_API_URL:-http://127.0.0.1:8080/route}"
  timeout_ms: 2000
  cache: "lcr"                         # a name from the cache: list (optional)
  cache_ttl_secs: 300                  # default TTL when the API omits one
  auth_header: "Bearer ${LCR_TOKEN}"   # optional
  fallback_gateway_group: "carrier-a"  # optional

cache:
  - name: "lcr"
    url: "redis://127.0.0.1:6379"
    local_ttl_secs: 60

gateway:
  groups:
    - name: "carrier-a"
      probe: { enabled: true, interval_secs: 15, failure_threshold: 3 }
      destinations:
        - { uri: "sip:gw1.carrier-a.example:5060", address: "198.51.100.11:5060", weight: 2 }
    - name: "carrier-b"
      probe: { enabled: true }
      destinations:
        - { uri: "sip:gw1.carrier-b.example:5060", address: "203.0.113.21:5060" }
```

The JSON contract is in [the LCR API reference](../reference/lcr-api.md); the
typed models operators build against ship in the `siphon-sip` SDK
(`from siphon_sdk.lcr import LcrRequest, LcrResponse, Route`).

## Charging (coming with Ro)

Today the winning carrier flows into the **CDR** via `cdr.write(call,
extra={...})` (shown above) — `carrier_id`, `rate`, `currency`. Auto-stamping
the carrier onto the **Rf** offline record (`outgoing-trunk-group-id`) and
**Ro** online credit teardown (drop the call when the OCS refuses further
credit) build on the B2BUA teardown hook and land once online charging merges.
Because LCR is B2BUA-only, that teardown path is available to it when it ships.
