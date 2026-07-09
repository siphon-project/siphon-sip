# Proxy & B2BUA

The `proxy` and `b2bua` namespaces register the event handlers that make
routing decisions, plus the helpers those handlers lean on (rate limiting,
sanity checks, ENUM lookup) and the generic SUBSCRIBE-dialog state store.

```python
from siphon import proxy, b2bua

@proxy.on_request
def route(request):
    request.relay()

@b2bua.on_invite
async def call(call):
    call.dial(call.ruri)
```

## `proxy` namespace

::: siphon_sdk.mock_module.MockProxy

## `proxy` utilities

Reached as `proxy.rate_limit`, `proxy.sanity_check`, `proxy.enum_lookup`, and
`proxy.memory_used_pct`.

::: siphon_sdk.mock_module.MockProxyUtils

## `b2bua` namespace

::: siphon_sdk.mock_module.MockB2bua

## `proxy.subscribe_state`

Generic SUBSCRIBE-dialog state (RFC 6665) for any event package, with optional
Redis-backed persistence.

::: siphon_sdk.mock_module.MockSubscribeState

## `SubscribeHandle`

A single subscription dialog returned by `proxy.subscribe_state.create(...)`.

::: siphon_sdk.mock_module.MockSubscribeHandle
