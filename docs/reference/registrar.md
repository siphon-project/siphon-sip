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

## `registrar` namespace

::: siphon_sdk.mock_module.MockRegistrar

## `registration` namespace

Outbound REGISTER client for carrier / trunk registration.

::: siphon_sdk.mock_module.MockRegistration
