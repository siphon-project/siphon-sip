# Info-Package over INFO (RFC 6086)

A small application protocol spoken inside a call: a client advertises a
package in `Recv-Info`, then sends and receives INFO requests of that package
for the life of the dialog. siphon gives the script the primitives and leaves
the package itself (its name, its payload, its rules) to it.

This recipe uses a made-up package, `example-package`, and shows the whole
loop on a B2BUA: advertising it, keeping it off the far leg, answering its INFO
requests locally, refusing what the script did not advertise, and sending the
package's own INFO from a task.

The primitives, each documented in [Call](../reference/call.md):

| Need | Primitive |
|---|---|
| Advertise the package on siphon's own answer | `call.answer(200, "OK", headers={"Recv-Info": ...})` |
| Advertise it on a 200 siphon relays | `reply.set_header("Recv-Info", ...)` in `@b2bua.on_answer` |
| Advertise it on the INVITE toward a subscriber | `call.set_header("Recv-Info", ...)` before `dial()` (or `b2bua.originate(headers=...)`) |
| Keep it off the other leg | `call.dial(..., strip=["Recv-Info", "Info-Package"])` |
| Answer an INFO here | `@b2bua.on_info` and `request.reply(...)` |
| Know which party sent it | the `leg` keyword of `@b2bua.on_info` |
| Send an INFO | `await b2bua.send_info(call_id, ..., leg=...)` |
| Remember what each party advertised | the `cache` namespace |

## What RFC 6086 asks of the script

These are the rules the script below follows; each is from the RFC.

- **Advertising (section 5.2.3).** The sender of an initial INVITE includes a
  `Recv-Info` header, empty if it wants no package. The receiver of a request
  that carries `Recv-Info` includes one in its reliable 18x or 2xx response. A
  UA does not include `Recv-Info` in a response if the request had none.
  siphon is two UAs in a B2BUA, so each leg is its own exchange: what the
  caller offered is answered on the A-leg, and what goes to the callee is
  whatever the script puts on the B-leg INVITE.
- **Sending (section 4.2.1).** A UA does not send an INFO for a package until
  the other party has indicated it will receive that package in this dialog,
  or after it has indicated it no longer will (an empty `Recv-Info` means
  none). The INFO carries an `Info-Package` header naming one package, and the
  package's data is the body part with `Content-Disposition: Info-Package`.
- **Receiving (section 4.2.2).** An INFO for a package the UA has not
  indicated willingness to receive gets `469 Bad Info Package` with a
  `Recv-Info` listing the packages it will receive. A 469 does not end the
  dialog (section 4.2.1, a transaction-only failure). Other errors (4xx, 5xx,
  6xx) are allowed as RFC 3261 says, and otherwise a well-formed INFO gets
  `200 OK`.
- **Responses (section 4.3.2).** A package's data does not go in an INFO
  response; it travels in INFO requests.

Because a B2BUA has a separate exchange on each leg, "willing to receive" is a
per-leg fact in both directions: what siphon told that leg, and what that leg
told siphon. The script below keeps both in the `cache` namespace, keyed by
Call-ID and leg (script state across requests belongs in `cache`, not in module
variables, and a cache backed by Redis survives a reload and is shared by the
nodes behind a load balancer).

Refusing a package INFO before the call is answered (`403`) is the script's own
policy, not something the RFC asks for; it is one of the "other error
responses" section 4.2.2 permits.

## Config

```yaml
cache:
  - name: "info-state"
    url: "redis://127.0.0.1:6379"
```

## The script

```python
import asyncio
from siphon import b2bua, cache

PACKAGE = "example-package"
CONTENT_TYPE = "application/example+json"
STATE = "info-state"          # the cache name from siphon.yaml


def packages(header_value):
    """The packages in one Recv-Info value (a comma separated list)."""
    return [name.strip() for name in (header_value or "").split(",") if name.strip()]


async def note(call_id, leg, side, header_value):
    """Remember what `side` ("local": siphon told the leg; "remote": the leg
    told siphon) advertised on `leg`. An empty Recv-Info is remembered as an
    empty list, which is not the same as never having advertised."""
    key = f"info:{call_id}:{leg}:{side}"
    await cache.store(STATE, key, "recv:" + ",".join(packages(header_value)), ttl=7200)


async def advertised(call_id, leg, side):
    """The packages, or None when nothing was ever advertised."""
    stored = await cache.fetch(STATE, f"info:{call_id}:{leg}:{side}")
    if stored is None:
        return None
    return packages(stored[len("recv:"):])


@b2bua.on_invite
async def on_invite(call):
    offered = call.get_header("Recv-Info")
    if offered is not None:
        # The caller speaks the package mechanism: remember what it will
        # receive, and that the 200 will tell it about ours.
        await note(call.call_id, "caller", "remote", offered)
        await note(call.call_id, "caller", "local", PACKAGE)
    # Nothing is advertised toward the callee: the presets pass Recv-Info
    # through, so strip it. The callee leg has no local advertisement.
    call.dial(
        "sip:15550100042@198.51.100.7:5060",
        strip=["Recv-Info", "Info-Package"],
    )


@b2bua.on_answer
async def on_answer(call, reply):
    # The 200 siphon relays advertises the package, but only to a caller that
    # sent Recv-Info (RFC 6086 section 5.2.3).
    if await advertised(call.call_id, "caller", "local") is not None:
        reply.set_header("Recv-Info", PACKAGE)
    # What the callee will receive, if it says (its 200's Recv-Info).
    theirs = reply.get_header("Recv-Info")
    if theirs is not None:
        await note(call.call_id, "callee", "remote", theirs)


@b2bua.on_info
async def on_info(call, request, leg):
    package = request.get_header("Info-Package")
    if package is None:
        return                       # DTMF and other INFO usages: relayed as before

    if call.state != "answered":
        request.reply(403, "Forbidden")
        return

    # Only a package siphon advertised to the party that sent it (section 4.2.2).
    accepted = await advertised(call.call_id, leg, "local") or []
    if package not in accepted:
        request.set_reply_header("Recv-Info", ", ".join(accepted))
        request.reply(469, "Bad Info Package")
        return

    request.reply(200, "OK")         # no body: package data is not sent in a response
    asyncio.create_task(push_state(call.call_id, leg))


async def push_state(call_id, leg):
    # Only to a party that said it will receive the package (section 4.2.1);
    # an empty Recv-Info is an empty list, which says none.
    theirs = await advertised(call_id, leg, "remote")
    if not theirs or PACKAGE not in theirs:
        return
    status = await b2bua.send_info(
        call_id,
        b'{"state": "active"}',
        CONTENT_TYPE,
        headers={"Info-Package": PACKAGE, "Content-Disposition": "Info-Package"},
        leg=leg,                     # back to the party that sent the INFO
        timeout_ms=5000,
    )
    # status is the final status code, or None if none arrived in time.


@b2bua.on_bye
async def on_bye(call, initiator):
    for leg in ("caller", "callee"):
        for side in ("local", "remote"):
            await cache.delete(STATE, f"info:{call.call_id}:{leg}:{side}")
```

### Advertising on the other paths

- **A call siphon answers itself** (no far leg): put it on the answer,
  `call.answer(200, "OK", body=sdp, content_type="application/sdp",
  headers={"Recv-Info": PACKAGE})`, and `note(..., "caller", "local", PACKAGE)`
  with it. As above, only when the INVITE carried `Recv-Info`. `Recv-Info` is
  not one of the headers siphon owns on that 2xx.
- **An INVITE siphon sends toward a subscriber**: the script is the UAC of that
  leg and so includes `Recv-Info` itself. `call.set_header("Recv-Info",
  PACKAGE)` before `call.dial(...)`, or `headers={"Recv-Info": PACKAGE}` on
  `b2bua.originate()`, and `note(..., "callee", "local", PACKAGE)`. Leave the
  `strip=` off that dial, or it removes it. The callee's own list arrives on
  its 200 (`reply.get_header("Recv-Info")` in `@b2bua.on_answer`, noted as
  above).
- **A `Recv-Info` that changes mid-call** (a re-INVITE or UPDATE carries a new
  set, section 5.2.2): `@b2bua.on_reoffer` sees it on `offer.request`; `note()`
  it again.

### What each branch of `on_info` does

| INFO | Answer | Relayed to the other leg |
|---|---|---|
| No `Info-Package` (DTMF, legacy usages) | the handler leaves it | yes (a call with one leg: a bare 200) |
| `Info-Package` before the call is answered | `403` | no |
| A package siphon did not advertise to that leg (including any package from the callee here) | `469` with `Recv-Info` listing what was advertised there | no |
| `example-package` from the caller | `200`, then a task sends the state INFO | no |

A DTMF INFO is also surfaced to `@rtpengine.on_dtmf`, whichever way it goes.

## Notes

- **The reply is recorded, not sent, until the handler returns.**
  `request.reply()` records the decision; siphon sends the response after the
  handler's coroutine completes. A task started with `asyncio.create_task` is
  independent of that and can run first, so the state INFO may be sent before
  the 200 to the INFO that caused it. They are two separate INFO transactions
  and RFC 6086 defines no delivery order between them (section 4.4: a package
  that needs one defines its own, for instance sequence numbers in its data).
  The usual order is the 200 first; it is not guaranteed.
- **Async handlers and the event loop.** A handler that starts a task needs the
  async driver, and siphon sends it there when its code names
  `asyncio.create_task`, `ensure_future`, `get_running_loop` or
  `get_event_loop`. A plain helper that reaches for the loop on the handler's
  behalf is not seen, so a handler with no `await` that calls one fails with
  `no running event loop`; add an `await` to the handler (any one, even
  `await asyncio.sleep(0)`).
- **`leg`** says which party sent the INFO, `"caller"` or `"callee"`, and is
  what `send_info(leg=)` takes. It also holds under `call.keep_call_id()`.
- **`b2bua.send_info` takes the SIP Call-ID** (`call.call_id`). Read it before
  starting the task rather than holding the `call` object across awaits.
- **Test it** without a server: `SipTestHarness.send_info(headers={"Info-Package":
  ...}, leg=...)` delivers an INFO to the handlers and returns the answer; see
  [Call](../reference/call.md). The script above is exercised that way in the
  SDK's own tests.
