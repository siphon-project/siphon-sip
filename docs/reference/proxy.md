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

As a subscriber, `handle = await proxy.subscribe_state.send(ruri, event=..., expires=...)`
sends the SUBSCRIBE and returns once the 2xx is in. The subscription exists from
the moment the SUBSCRIBE leaves, because the notifier's first NOTIFY may arrive
before that 2xx (RFC 6665 §4.1.2.4). siphon matches such a NOTIFY on Call-ID, the
To tag and the Event header and establishes the dialog from it (§4.4.1), route
set included, before the NOTIFY handler runs. So
`proxy.subscribe_state.find(request.call_id, request.to_tag, request.from_tag)`
returns the same handle in either order, and `None` means the NOTIFY belongs to
no subscription: answer it 481.

What the SUBSCRIBE transaction then decides, per the subscriber state machine of
§4.1.2:

| The SUBSCRIBE gets | after a NOTIFY established the subscription | with no NOTIFY yet |
|---|---|---|
| a 2xx | `send()` returns the handle; the dialog stays the NOTIFY's | `send()` returns the handle; the 2xx establishes the dialog |
| no final response within `timeout_ms` | `send()` returns the handle: the subscription stands | `send()` raises; nothing is left |
| a non-2xx | `send()` raises; the subscription is withdrawn (§4.1.2.1) | `send()` raises; nothing is left |

A NOTIFY with `Subscription-State: terminated` ends the subscription in any
order. The NOTIFY handler still finds it with `find()` and answers 200; siphon
removes it when the handlers have returned (§4.4.1), after which the handle
raises `LookupError`.

The 2xx and the NOTIFYs travel separately and race, so what `send()` returns
depends on which of them arrived and never on their order. A terminating NOTIFY
is reported to the NOTIFY handler and nowhere else: `send()` returns the handle
on the 2xx whether that NOTIFY came first or second, and in both cases the
subscription no longer exists once the handler has returned. A one-shot fetch
(`expires=0`) therefore reads its result in the NOTIFY handler and gets back a
handle that is already spent.

One `send()` tracks one dialog: the first NOTIFY's, or the 2xx's when no NOTIFY
came before it. A NOTIFY for the same SUBSCRIBE from another notifier tag, which
a forked SUBSCRIBE produces, is answered 481 by siphon without running the
handler, and a 2xx from another fork does not change the dialog (§5.4.9).

What the dialog holds is the notifier's to say, and is likewise the same in
either order:

- **Duration.** `handle.expires` is the shortest the notifier has stated, in the
  `Expires` of the 2xx (§4.1.2.1) or the `expires` of a NOTIFY's
  Subscription-State (§4.1.2.2). Only `handle.refresh()` lengthens it. Schedule
  the refresh from `handle.expires`, not from the value you asked for.
- **Target.** A NOTIFY is a target refresh request, so its Contact is where the
  next `handle.refresh()` or `handle.terminate()` goes (§4.4.1). The 2xx
  supplies the target only until a NOTIFY has.
- **Route set.** Fixed by whichever message established the dialog (RFC 3261
  §12.1). A 2xx that would have given another one is logged at `warn`.

Four things end a subscription before it expires:

| What happened | What siphon does |
|---|---|
| A NOTIFY with `Subscription-State: terminated` | Removes it once the NOTIFY handlers have returned |
| `handle.terminate()` | Sends SUBSCRIBE `Expires: 0`; the subscription stays until the notifier's terminating NOTIFY (§4.1.2.3), which the handler finds and answers 200, or 32 s (Timer N) |
| A 2xx with no NOTIFY inside 32 s (Timer N, §4.1.2.4) | Removes it: the attempt failed |
| A non-2xx after `send()` had returned on its timeout | Removes it: no subscription was created (§4.1.2.1) |

A subscription read back with `proxy.subscribe_state.get(id)`, after a restart or
on another replica, is tracked the same way from the moment it is loaded.

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
