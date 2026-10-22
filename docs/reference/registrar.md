# Registrar

The `registrar` namespace is the location service: it saves contact bindings,
looks them up, and handles the IMS implicit registration set, service routes,
and pending/confirm flows. The `registration` namespace is the opposite
direction — outbound REGISTER to upstream carriers and SBCs.

```python
from siphon import registrar

@proxy.on_request("REGISTER")
async def register(request):
    if await auth.verify_digest(request, "example.com"):
        registrar.save(request)   # saves contacts and sends 200 OK
    else:
        await auth.require_www_digest(request, "example.com")
```

When the registrar refuses a binding, `registrar.save()` answers the REGISTER
itself, returns `False` and stores nothing. None of the REGISTER's Contacts are
kept, and with `force=True` the existing bindings stay.

| Refusal | Answer |
|---|---|
| `Expires` below `registrar.min_expires` | `423 Interval Too Brief` with `Min-Expires` (RFC 3261 §10.3 step 7) |
| A new binding past `registrar.max_contacts` | `503 Service Unavailable` with `Retry-After`: seconds until the soonest held binding expires, 1 to `max_expires` |
| An AoR that is not a safe storage key | `404 Not Found` (RFC 3261 §10.3 step 3) |
| `Contact: *` beside another Contact entry (on the same line or another), or with an `Expires` that is absent or not zero | `400 Bad Request` (RFC 3261 §10.3 step 6); only `Contact: *` alone with `Expires: 0` removes every binding |

Each refusal is logged at warn and counted in
`siphon_registrar_refusals_total{reason}` (`interval_too_brief`,
`too_many_contacts`, `invalid_aor`, `invalid_wildcard`). `registrar.save_proxy()` never answers a
request, so it still raises `ValueError` for the same conditions.

## `registrar` namespace

::: siphon_sdk.mock_module.MockRegistrar

## `registration` namespace

Outbound REGISTER client for carrier / trunk registration.

::: siphon_sdk.mock_module.MockRegistration

### One process, many IMS UEs

An outbound registration can register from an address of its own instead of
the process's. That is what lets one process act as many IMS UEs, each from
its own address. The walkthrough is the
[IMS multi-UE cookbook](../cookbook/ims-multi-ue.md).

```python
registration.add(
    "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
    "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060",
    user="001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
    auth="aka", k=k, opc=opc,
    ipsec=True, ue_port_c=6100, ue_port_s=6101,
    imei="01234567-000001-0", ims_features=["mmtel", "smsip"],
    local_addr="203.0.113.11",      # IP only
    require_local_addr=True,        # never fall back to the process's address
    refresh_window=(0.4, 0.6),      # overrides registrant.refresh_window
)
```

| Argument / method | Meaning |
|---|---|
| `add(..., local_addr=None)` | The IP this entry registers from: Via and Contact host, the UDP source of every REGISTER (initial, 401 retry, de-REGISTER), and with `ipsec=True` the UE side of its SAs, the protected REGISTER leaving from `local_addr:ue_port_c`. siphon opens the sockets itself (IP_FREEBIND), so the address need not exist yet and no `listen.udp` entry is needed. UDP only. |
| `add(..., require_local_addr=False)` | `True`: never register from the process's address. Without `local_addr` the entry waits as `awaiting_address`. |
| `add(..., refresh_window=None)` | `(low, high)` fractions of the granted Expires, drawn per refresh; `0 < low <= high < 1`. `None`: `registrant.refresh_window`. |
| `set_local_addr(aor, ip_or_None) -> bool` | Move the entry. Restating the current address is a no-op, so it can run on a timer. A real move deletes the old SA pair and starts a fresh registration from the new address at once, keeping the Call-ID. `None` puts an entry that has had an address (or has `require_local_addr`) in `awaiting_address`; any other entry falls back to the process's address. `False` when there is no such AoR. |
| `find_by_local("ip" \| "ip:port") -> str \| None` | The AoR registering from that address, for MT routing: pass `call.flow.local_addr` or `request.flow.local_addr`. With a port, the entry owning that port (plain, protected client or protected server); without, the first entry on the address. A linear scan, meant for once per call. |
| `counts() -> dict` | Registrations per state, every state present (zero when empty). |
| `list()` | Each dict also carries `local_addr` (str or `None`), `failure_count` and `last_failure_status` (int or `None` once an attempt succeeded). |
| `flow(aor, ue_ip=None)` | `ue_ip` defaults to the entry's `local_addr`; it is required (`ValueError`) for an entry on the process's address. |

`add` and `set_local_addr` raise `ValueError` when another entry already
registers from the same `(local_addr, ue_port_c)`, for a `local_addr` on a
`tcp` or `tls` entry, and for a malformed window.

States are `unregistered`, `registering`, `challenging`, `registered`,
`failed` and `awaiting_address`. `@registration.on_change` gets
`awaiting_address` as an `event_type` when an entry loses its address.

Limits:

- **UDP only.** The outbound connection pool opens stream connections from an
  ephemeral source the entry's address would not name.
- **A move does not de-register the old binding.** The old address is usually
  gone, so nothing could carry the de-REGISTER. A registrar that keys on
  `+sip.instance` (RFC 5626, built from `imei`) replaces the binding with the
  new one; any other lets it lapse at its Expires.
- **`remove()` of an IPsec entry leaves its SAs installed** until their hard
  lifetime runs out, as it always has.
- **Three sockets per IPsec UE** (plain, protected client, protected server),
  so the descriptor limit has to cover three per UE plus the base set.
- **The Contact port is the plain UDP port**, the first `listen.udp` port, as
  for a single UE.
- **Identity overlay:** an MT request that arrives on a per-UE socket is
  answered with that socket's own address in Contact and Via, not
  `advertised_address`, and the per-UE addresses count as this node when Route
  entries are consumed.
