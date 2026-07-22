# LCR API contract (v1)

The JSON contract between siphon and the external Least-Cost-Routing API. siphon
`POST`s an `LcrRequest` to `lcr.api_url` and expects an `LcrResponse`. LCR is
B2BUA-only — see the [cookbook](../cookbook/least-cost-routing.md).

Typed models operators build against ship in the `siphon-sip` SDK:

```python
from siphon_sdk.lcr import LcrRequest, LcrResponse, Route, LcrReject
```

A runnable reference server (FastAPI) is
[`examples/lcr_api_server.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/lcr_api_server.py).

## Request (siphon → API)

`POST {api_url}` with `Content-Type: application/json` and the configured
`auth_header` (if any) as `Authorization`.

```json
{
  "version": "1",
  "call_id": "abc123@10.0.0.1",
  "from": "sip:+13105550100@sbc.example.com",
  "to": "sip:+12025550123@sbc.example.com",
  "dialed_number": "+12025550123",
  "source": {
    "ip": "192.0.2.50",
    "trunk_group": "cust-trunks",
    "transport": "udp"
  },
  "attributes": { "customer_id": "cust-42" }
}
```

| Field | Type | Notes |
|---|---|---|
| `version` | string | Contract version, currently `"1"`. |
| `call_id` | string | A-leg Call-ID (for API-side correlation). |
| `from` / `to` | string | A-leg From / To URIs. |
| `dialed_number` | string | The number to rate — normalized by the script (canonical `+E.164` recommended). |
| `source.ip` | string | A-leg source IP. |
| `source.trunk_group` | string? | Ingress trunk, if the script set it. Part of the cache key. Omitted when unset. |
| `source.transport` | string | `udp` \| `tcp` \| `tls` \| `ws` \| `wss`. |
| `attributes` | object | Free-form script hints. Omitted when empty. |

## Response (API → siphon)

```json
{
  "routes": [
    { "carrier_id": "carrier-a", "gateway_group": "carrier-a",
      "rate": 0.0042, "currency": "USD", "billing_increment": 60, "timeout_secs": 12 },
    { "carrier_id": "carrier-b", "next_hop": "sip:203.0.113.21:5060", "rate": 0.0051 }
  ],
  "cache_ttl_secs": 300,
  "reject": null
}
```

Ordered `routes` (cheapest / most-preferred first). Each route needs at least
one of `gateway_group` / `next_hop` / `ruri`.

| Route field | Type | Notes |
|---|---|---|
| `carrier_id` | string | Opaque id, carried into CDR/charging. Never routed on. |
| `gateway_group` | string? | A `gateway:` pool — siphon dials a healthy member, skips the route if the pool is down. Preferred (health-probed). |
| `next_hop` | string? | Explicit next-hop URI (when no group, or to pin the wire destination). |
| `ruri` | string? | Full Request-URI override (carrier IMPU shape / number format). |
| `tech_prefix` | string? | Dial/tech-prefix prepended to the R-URI userpart for this carrier (e.g. `"1010288"`). |
| `number_policy` | string? | Named `number_policies:` preset applied to this carrier's B-leg From/To/PAI (per-carrier CLI/identity shape). R-URI stays controlled by `tech_prefix`/`ruri`. |
| `rate` | number? | Per-minute rate (CDR/charging). |
| `currency` | string? | ISO 4217. |
| `billing_increment` | int? | Seconds (60 = per-minute, 1 = per-second). |
| `min_duration` | int? | Minimum billable seconds. |
| `timeout_secs` | int? | Per-attempt ring timeout (else the call-level default). |
| `headers` | object? | Headers to inject on this carrier's B-leg INVITE (applied after the header policy). |
| `cdr_fields` | object? | Fields siphon auto-stamps onto the CDR when this carrier wins (no per-field script). |
| `reroute_causes` | int[]? | SIP codes from this carrier that fail over to the next (overrides per-gateway + global). |

Top-level:

| Field | Type | Notes |
|---|---|---|
| `routes` | array | Ordered carriers. Empty + `reject: null` = no route (script answers 4xx/5xx). |
| `cache_ttl_secs` | int? | How long siphon may cache this decision. `0`/absent = do not cache. |
| `reject` | object? | `{ "code": int, "reason": string }` — siphon rejects the call with this instead of routing (API-side block). |

## Behavior notes

- **Caching** — keyed by `{trunk_group}:{dialed_number}` in `lcr.cache`, for
  `cache_ttl_secs` (or `lcr.cache_ttl_secs`). Redis-backed caches are shared
  fleet-wide.
- **Fallback** — on transport error / timeout / 5xx, siphon uses
  `lcr.fallback_gateway_group` if set (a synthesized single-route decision),
  else the script sees `None`.
- **Reroute** — a carrier failure fails over to the next carrier only when its
  code is a reroute cause (per-route `reroute_causes` > per-gateway
  `gateway.groups[].reroute_causes` > global `lcr.reroute_causes`, default
  `[408, 500, 502, 503, 504]`). A definitive response (486, 603) is forwarded to
  the caller.
- **Forward-compatibility** — unknown response fields are ignored; new optional
  fields can be added without a version bump. Bump `version` only on a breaking
  change.
