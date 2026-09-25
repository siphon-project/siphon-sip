# Gateway provisioning contract (v1)

The JSON a `gateway.backend: http` source answers with, so a controller that
owns its carriers as data can hand siphon the list instead of having them
written into `siphon.yaml` by hand.

The models are typed in [`siphon_sdk.gateways`](https://pypi.org/project/siphon-sip/)
and mirrored by the Rust structs in `src/gateway/source.rs`. A runnable
reference server — serving this and the
[registrant contract](registrant-api.md) off one table — is
`examples/provisioning_api_server.py`.

```python
from siphon_sdk.gateways import GatewayListResponse, GatewayRow
```

## Configuration

```yaml
gateway:
  backend: http                 # static (default) | database | http
  http:
    url: "http://127.0.0.1:8080/gateways"
    refresh_secs: 30
    timeout_ms: 2000
    auth_header: "Bearer ${PROVISIONING_TOKEN}"
```

The SQL form reads the same fields as columns:

```yaml
gateway:
  backend: database
  database:
    url: "postgresql://siphon@db.internal/siphon"
    query: 'SELECT "group", uri, address, transport, weight, priority,
             username, password, registers, enabled, probe FROM gateways
             WHERE node = $1'
    refresh_secs: 30
```

`group` (or `group_name`, since `group` is a reserved word) and `uri` are
required; every other column is optional. `probe` and `require_registration`
are `boolean` columns, the `probe_*` counts integers. When the statement references `$1`,
siphon binds `server.instance_id` to it.

## Response (source → siphon)

`GET {url}` returns the **complete desired state**, not a delta. One row is one
destination; rows are gathered into groups by `group`.

```json
{
  "version": "1",
  "gateways": [
    {
      "group": "carriers",
      "uri": "sip:gw1.carrier.example:5060",
      "weight": 3,
      "priority": 1,
      "attrs": {"region": "eu-west"},
      "registers": "sip:trunk1@carrier.example",
      "require_registration": true,
      "enabled": true
    }
  ]
}
```

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `group` | string | — | The name `gateway.select()` takes |
| `uri` | string | — | SIP URI to route to |
| `address` | string | from the URI host | Socket address; a hostname is re-resolved each probe cycle |
| `transport` | string | URI param, then `udp` | `udp`, `tcp` or `tls` |
| `weight` | int | `1` | Weighted round-robin weight |
| `priority` | int | `1` | Lower is tried first; a higher tier is a failover pool |
| `algorithm` | string | `"weighted"` | Group-wide: `weighted`, `round_robin`, `hash` |
| `attrs` | object | `{}` | Matched by `gateway.select(attrs=…)` |
| `source_networks` | array | `[]` | Group-wide source CIDRs for `from_gateway()` |
| `probe` | bool | `true` | Group-wide: health-probe with `OPTIONS` ([probe policy](#probe-policy)) |
| `probe_interval_secs` | int | `30` | Group-wide: seconds between probes; `0` is refused |
| `probe_failure_threshold` | int | `3` | Group-wide: failed probes before a destination is marked down |
| `probe_from_user` | string | `"siphon"` | Group-wide: user part of the probe's `From` |
| `probe_from_domain` | string | local address | Group-wide: host part of the probe's `From` |
| `username` | string | — | Digest username this destination challenges with |
| `password` | string | — | Plaintext password. Supply this **or** `ha1` |
| `ha1` | string | — | `H(username:realm:password)` hex |
| `ha1_algorithm` | string | `"md5"` | Hash `ha1` was computed with |
| `registers` | string | — | AoR of the outbound registration this destination belongs to |
| `require_registration` | bool | `false` | Withhold from selection while `registers` is down |
| `enabled` | bool | `true` | `false` drops the destination without removing the row |

## Probe policy

A source group is probed with `OPTIONS` every 30 s unless its rows say
otherwise, which is also what a `gateway.groups` entry does. The `probe_*`
fields are the row form of that entry's `probe:` block, and are group-wide:
each is taken from the first row of the group that carries it, so they can sit
on one row or on all of them.

Turn probing off for a carrier that does not answer `OPTIONS`. Probed anyway,
it fails its probe, its destinations are marked down and selection skips them:
the carrier is taken out of service by being provisioned. Moving a
hand-written group with `probe.enabled: false` to a source means carrying that
`false` across as `"probe": false`.

Set `probe_from_user` / `probe_from_domain` for a carrier that rejects an
`OPTIONS` whose `From` it does not recognise. A probe rejected that way looks
exactly like a carrier that is down.

- **A change keeps what the prober learned.** Changing any `probe_*` field
  replaces the group, because a prober's period and `From` are fixed when it
  starts, but its destinations carry over with their health, failure count and
  `Retry-After` cooldown. A poll that changes none of them leaves the group and
  its prober alone.
- **Switching probing off puts the prober's verdicts back in service.** A
  destination the prober had marked down is marked up again, because with no
  prober nothing ever would. This is the migration case above: the carrier went
  down for not answering `OPTIONS`, not for being down.
- **An unprobed group has no prober to re-resolve it.** A hostname
  destination's send address is resolved once, when the destination is built,
  exactly as for a `gateway.groups` entry with `probe.enabled: false`. Its
  membership for `from_gateway()` is re-resolved on the kernel allow set's floor
  tick when [that set](../kernel-firewall.md#gateway-allow-set) is on.

```json
{"group": "carriers", "uri": "sip:gw1.carrier.example:5060", "probe": false}
```

```json
{"group": "carriers", "uri": "sip:gw1.carrier.example:5060",
 "probe_interval_secs": 15, "probe_from_domain": "sbc.example.com"}
```

## Linking a destination to its registration

`registers` names an AoR from the [registrant source](registrant-api.md). It
does two things:

- **The credential is defined once.** A destination with no `username` of its
  own answers a `401`/`407` with that registration's credential, so rotating a
  trunk password is one edit rather than two that drift apart.
- **`require_registration: true` gates selection.** While that registration is
  not registered, the destination is skipped by `gateway.select()`. This is
  opt-in because silently withholding a destination is worse than trying it: a
  gateway that authenticates per call does not need its registration up. Turn it
  on for a carrier that only accepts calls from a registered peer, where dialling
  it unregistered just earns a `403`.

A `require_registration` with no `registers` to gate on is refused as a row.

## Typed contract models

`siphon_sdk.gateways` is the single typed source for the shapes above —
zero-dependency dataclasses. Build your endpoint against them:

```python
from fastapi import FastAPI
from siphon_sdk.gateways import GatewayListResponse, GatewayRow

app = FastAPI()

@app.get("/gateways")
def gateways() -> dict:
    return GatewayListResponse(gateways=[
        GatewayRow(group="carriers", uri="sip:gw1.carrier.example:5060",
                   weight=3, registers="sip:trunk1@carrier.example"),
    ]).to_dict()
```

### `GatewayListResponse`

| Field | Type | Default | Meaning |
| ----- | ---- | ------- | ------- |
| `gateways` | `list[GatewayRow]` | `[]` | The complete desired state |
| `version` | `str` | `"1"` | Contract version; a mismatch is logged, not fatal |

### `GatewayRow`

`group` and `uri` are required positionally; everything else is
keyword-with-default and maps one-to-one onto the JSON fields above.

## Behavior notes

- **Health survives a refresh.** A destination whose definition has not changed
  is carried over as the same object, keeping what the health prober has learned
  about it. Rebuilding the group every poll would mark every dead carrier
  healthy again on a 30-second cycle and route calls straight back into it.
- **An unchanged group is not touched at all.** Replacing a group restarts its
  health prober, so a poll that finds nothing different leaves it alone.
- **A changed definition is a new destination.** Change the URI, address,
  transport, weight, priority, attributes or credentials and it is rebuilt,
  starting healthy — correct, because it is a different peer or a different way
  of reaching one.
- **An unreadable source changes nothing.** A failed read keeps the current
  groups, so a database being briefly down does not leave the node with nowhere
  to route. An endpoint that cannot answer should fail the request rather than
  return an empty list.
- **The source owns only what it created.** Groups from `gateway.groups` and
  ones a script created with `gateway.add_group()` are never replaced or removed
  by a reconcile, and a group name one of them already holds is skipped with a
  warning.
- **A malformed row is skipped, not fatal.** One bad gateway must not take the
  rest of the estate with it; it is counted and logged with its group and URI.
- **Push, when polling is too slow.** `POST /admin/gateways/refresh` applies a
  change the moment the controller saves a row.
- **If your carriers authenticate by source address, turn on the kernel allow
  set.** Provisioning a carrier here makes it dialable; it does not make the
  kernel accept its answers. With `security.firewall.gateway_set` (the default
  when `security.firewall` is set at all) siphon publishes every address these
  groups resolve to into an nftables set you reference from your own ruleset, on
  the same reconcile that made the carrier dialable. See
  [kernel-firewall.md](../kernel-firewall.md#gateway-allow-set). Without it, a
  newly provisioned carrier works outbound and is silently dead inbound.
