# Migrating to 1.10.0

1.10.0 makes every scripting API that waits on the network **awaitable**. If a
script calls one of them, it has to `await` it, and the handler has to be
`async def`.

This is the only breaking change in the release. Nothing else about the API
moved.

## Why

These APIs used to block the thread that called them. For an `async def`
handler that thread is its **asyncio driver** — one of a small pool
(`script.async_pool_size`, defaulting to the CPU count), each running many
coroutines at once. While one was blocked the whole loop stopped: every
coroutine on it, including ones belonging to calls that never touched the API.

On a two-core node that is two loops. A handful of concurrent Diameter requests,
credential lookups or DNS resolutions could stall async dispatch across the
whole process.

1.9.1 bounded the worker-side wait so a wedged handler could no longer abort the
node. Nothing could release a *driver*.

## What changed

| Namespace | Methods |
|---|---|
| `diameter` | `cx_uar`, `cx_sar`, `cx_lir`, `s6a_air`, `s6a_ulr`, `s6a_purge_ue`, `rx_aar`, `rx_str`, `sh_udr`, `sh_pur`, `sh_snr`, `s6c_srr`, `s6c_rsr`, `sgd_tfr`, `send_request`, `rf_acr_start`, `rf_acr_interim`, `rf_acr_stop`, `rf_acr_event` |
| `sbi` | `discover_pcf_binding`, `create_session`, `update_session`, `delete_session` |
| `auth` | `require_www_digest`, `require_proxy_digest`, `require_digest`, `verify_digest`, `require_ims_digest` |
| `presence` | `notify`, `terminate` |
| `subscribe_state` | `get`, `send`; a handle's `notify`, `terminate`, `refresh` |
| `proxy` | `send_request` |

### Not changed

`auth.require_aka_digest` derives its vectors locally with Milenage and performs
no I/O, so it stays synchronous. So do `auth.stamp_integrity_protected` and
`auth.verify_integrity_protected`, and every registrar, SDP, header and logging
call.

`SubscribeHandle`'s properties (`event`, `expires`, `local_tag`, …) also stay
synchronous. A Python property cannot be awaited, so they read through a loader
that still blocks on an L2 (Redis) miss. An L1 hit — the common case, and always
the case for a dialog this instance created — touches no network.

## Migrating

Add `await`, and make the handler `async def` if it is not already:

<!-- await-gate: shows the pre-1.10 form on purpose -->
```python
# before
@proxy.on_request("REGISTER")
def handle_register(request):
    if not auth.require_digest(request, realm=REALM):
        return
    registrar.save(request)

# after
@proxy.on_request("REGISTER")
async def handle_register(request):
    if not await auth.require_digest(request, realm=REALM):
        return
    registrar.save(request)          # unchanged — the registrar is synchronous
```

A handler can be `async def` whether or not it awaits anything; siphon detects
which it is at decoration time and dispatches accordingly. Converting a handler
costs nothing on its own.

If a helper function of yours calls one of these, it becomes `async def` too,
and its callers must await it — all the way up to the handler.

## The two failure modes, and how to tell them apart

**You forgot to make the handler `async def`.** The call raises immediately:

```
RuntimeError: this siphon API is awaitable and needs a running event loop:
call it with `await` from an `async def` handler. A synchronous handler cannot
await, so change `def handler(...)` to `async def handler(...)`.
```

Loud, and it names the fix.

**You forgot the `await` itself.** This one is quiet and it is the dangerous
one. The call returns a coroutine, which is **truthy**, so:

<!-- await-gate: demonstrates the missing-await bug on purpose -->
```python
if not auth.require_digest(request, realm=REALM):   # missing await
    return                                          # never taken
```

never challenges, and the request is treated as authenticated. The same shape
hides a NOTIFY that is never sent and a Diameter request that never leaves.

Python does flag it, as a warning on stderr:

```
RuntimeWarning: coroutine 'AuthNamespace.require_digest' was never awaited
```

**Treat that warning as an error.** In a script under test, turn it into one:

```python
import warnings
warnings.filterwarnings("error", message="coroutine .* was never awaited")
```

The shipped scripts and examples are all converted, and the SDK mocks mirror the
awaitable/synchronous split exactly, so `pytest` against `siphon-sip` catches a
missing `await` in your own scripts the same way siphon would.

## Ordering

`await` is sequencing, so ordering is preserved for free: two requests a handler
sends in order still leave in that order. No queue, no special case.

One consequence is worth stating plainly. `proxy.send_request` used to put the
message on the wire *before* it handed back its coroutine, so a script that
never awaited it still sent. That is no longer true: an un-awaited
`send_request` sends nothing.

## Validation

Arguments are still read, and still validated, at the call rather than on
`await` — the Python objects cannot cross into the future. A malformed
`rx_aar` media component, a bad `specific_actions`, a `password=` and `ha1=`
supplied together: all still raise where you called them.
