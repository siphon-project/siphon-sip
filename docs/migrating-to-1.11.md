# Migrating to 1.11.0

One thing was removed from the scripting API. Everything else in this release is
additive or a narrowing of behaviour in a corner, described at the bottom.

## Removed: `SubscribeHandle.mirror_reply()`

It took a `Reply`, discarded it, and returned `False`. It sent no NOTIFY and
changed no state — a placeholder for a convenience that was never built.

Nothing can have depended on what it did, because it did nothing. What changes is
the call itself: it now raises `AttributeError`, which in a handler is a hard
runtime failure. Grep your scripts for `mirror_reply`.

Use the awaited `notify()`:

```python
# before — returned False, sent nothing
handle.mirror_reply(reply)

# after
await handle.notify(body=body, content_type="application/reginfo+xml")
```

`mirror_reply` was documented as "`notify()` without the automatic
`active;expires=…` default". That is what `state=` is for, so if you were
reaching for it to control `Subscription-State`, pass the header value you want:

```python
await handle.notify(body=body, content_type=content_type, state="pending")
await handle.notify(body=body, content_type=content_type,
                    state="active;expires=60;reason=probation")
```

The Python scripting API may break on a minor release and never on a patch, which
is why this lands in 1.11.0. See the versioning policy at the top of
`CHANGELOG.md`.

## Not a migration, but worth knowing

`SubscribeHandle`'s properties (`event`, `expires`, `local_tag`,
`event_version`) no longer read through a loader that could block on the L2
cache, so they can no longer stall the asyncio driver of an `async def` handler.
They stay properties and stay live reads — there is nothing to rewrite.

One behaviour narrowed with it: a property on a dialog whose local entry has
already been reaped (expired, or terminated) now raises `LookupError` instead of
being revived from a cache copy whose terminating NOTIFY has already gone out.
If you want that re-read, ask for it:

```python
if not await handle.reload():
    return                      # the subscription is gone
log.info(f"{handle.expires}s left")
```

`reload()` is new in 1.11.0 and is awaitable, so it needs `await` and an
`async def` handler — see [Migrating to 1.10](migrating-to-1.10.md) for what that
means and the two ways forgetting it shows up.
