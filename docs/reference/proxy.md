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

Use `handle = proxy.subscribe_state.accept(request, expires=seconds)` after
authenticating the subscriber and authorizing the event package and resource.
It stages the 200 response with the dialog's To-tag and negotiated Expires,
which siphon sends when the handler returns. An unknown in-dialog request
receives 481 and returns `None`. Refresh returns the same handle without
resetting NOTIFY CSeq or event-body version. Immediately
`await handle.notify(body=..., content_type=...)`; for Expires zero,
`await handle.terminate(reason="deactivated", body=..., content_type=...)` instead.
A NOTIFY sent from the handler that accepted the subscription is held until that
handler returns and goes on the wire after the 200 (RFC 6665 §4.1.2.3). One sent
later, from a timer or a background task, goes out immediately.
The notifier tag is available as `handle.local_tag`. Expiry sends a terminating
NOTIFY automatically; scripts still own package content and change notifications.

Direct subscriptions remember the received peer and transport. Background NOTIFY
uses that exact live stream, never another phone sharing the same proxy address;
a closed stream fails visibly. The Contact remains the NOTIFY Request-URI.
Subscriptions with Record-Route follow their established route set.

::: siphon_sdk.mock_module.MockSubscribeState

## `SubscribeHandle`

A single subscription dialog returned by `proxy.subscribe_state.create(...)`.

Its properties read this instance's own dialog state, so none of them can wait
on the network — which is what makes them safe to touch from an `async def`
handler, where blocking would stop every other coroutine on that asyncio driver.
They are still live reads, not a snapshot: a SUBSCRIBE refresh landing on the
store shows up through a handle built before it. Once the dialog is gone
(terminated, or reaped on expiry) they raise `LookupError` rather than answering
stale, and `await handle.reload()` is the explicit re-read through the L2 cache
for the cross-replica case.

::: siphon_sdk.mock_module.MockSubscribeHandle
