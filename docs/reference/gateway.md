# Gateway

The `gateway` namespace manages named groups of SIP destinations with health
probing and pluggable load-balancing (round-robin, weighted, consistent hash).

```python
from siphon import gateway

gw = gateway.select("carriers", key=request.call_id)
if gw:
    request.relay(gw.uri)
```

## `gateway` namespace

::: siphon_sdk.mock_module.MockGateway

## `Destination`

A single destination returned by `gateway.select()` / `gateway.list()`.

::: siphon_sdk.mock_module.MockDestination
