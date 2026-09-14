# Registrar

The `registrar` namespace is the location service: it saves contact bindings,
looks them up, and handles the IMS implicit registration set, service routes,
and pending/confirm flows. The `registration` namespace is the opposite
direction — outbound REGISTER to upstream carriers and SBCs.

```python
from siphon import registrar

@proxy.on_request("REGISTER")
def register(request):
    if auth.verify_digest(request, "example.com"):
        registrar.save(request)   # saves contacts and sends 200 OK
    else:
        auth.require_www_digest(request, "example.com")
```

When the registrar refuses a binding, `registrar.save()` answers the REGISTER
itself, returns `False` and stores nothing. None of the REGISTER's Contacts are
kept, and with `force=True` the existing bindings stay.

| Refusal | Answer |
|---|---|
| `Expires` below `registrar.min_expires` | `423 Interval Too Brief` with `Min-Expires` (RFC 3261 §10.3 step 7) |
| A new binding past `registrar.max_contacts` | `503 Service Unavailable` with `Retry-After`: seconds until the soonest held binding expires, 1 to `max_expires` |
| An AoR that is not a safe storage key | `404 Not Found` (RFC 3261 §10.3 step 3) |

Each refusal is logged at warn and counted in
`siphon_registrar_refusals_total{reason}` (`interval_too_brief`,
`too_many_contacts`, `invalid_aor`). `registrar.save_proxy()` never answers a
request, so it still raises `ValueError` for the same conditions.

## `registrar` namespace

::: siphon_sdk.mock_module.MockRegistrar

## `registration` namespace

Outbound REGISTER client for carrier / trunk registration.

::: siphon_sdk.mock_module.MockRegistration
