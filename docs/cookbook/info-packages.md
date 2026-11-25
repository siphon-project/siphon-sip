# Info-Package over INFO (RFC 6086)

A small application protocol spoken inside a call: a client advertises a
package in `Recv-Info`, then sends and receives INFO requests of that package
for the life of the dialog. siphon gives the script the primitives and leaves
the package itself (its name, its payload, its rules) to it.

This recipe uses a made-up package, `example-package`, and shows the whole
loop on a B2BUA: advertising it, keeping it off the far leg, answering its INFO
requests locally, refusing what the script does not accept, and sending the
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

## What RFC 6086 asks of the script

These are the rules the script below follows; each is from the RFC.

- **Advertising (section 5.2.3).** The sender of an initial INVITE includes a
  `Recv-Info` header, empty if it wants no package. The receiver of a request
  that carries `Recv-Info` includes one in its reliable 18x or 2xx response. A
  UA does not include `Recv-Info` in a response if the request had none.
  siphon is two UAs in a B2BUA, so each leg is its own exchange: what the
  caller offered is answered on the A-leg, and what goes to the callee is
  whatever the script puts on the B-leg INVITE.
- **Sending (section 4.2.1).** An INFO for a package is sent only after the
  other party has advertised it, and carries an `Info-Package` header naming
  one package. The package's data is the body part with `Content-Disposition:
  Info-Package`.
- **Receiving (section 4.2.2).** An INFO for a package the UA has not
  advertised gets `469 Bad Info Package` with a `Recv-Info` listing what it
  will take. A 469 does not end the dialog (section 4.2.1, a transaction-only
  failure). The UA may answer other errors (4xx, 5xx, 6xx) as RFC 3261 says,
  and otherwise a well-formed INFO gets `200 OK`.
- **Responses (section 4.3.2).** A package's data does not go in an INFO
  response; it travels in INFO requests.

Refusing a package INFO before the call is answered (below, `403`) is the
script's own policy, not something the RFC asks for; it is one of the "other
error responses" section 4.2.2 permits.

## The script

```python
import asyncio
from siphon import b2bua

PACKAGE = "example-package"
CONTENT_TYPE = "application/example+json"


def advertised(value):
    """The packages in one Recv-Info value (a comma separated list)."""
    return [name.strip() for name in (value or "").split(",") if name.strip()]


@b2bua.on_invite
def on_invite(call):
    # The caller offered the package in its INVITE's Recv-Info. It stays off
    # the callee's leg: the presets pass Recv-Info through, so strip it.
    call.dial(
        "sip:15550100042@198.51.100.7:5060",
        strip=["Recv-Info", "Info-Package"],
    )


@b2bua.on_answer
def on_answer(call, reply):
    # The 200 siphon relays to the caller advertises the package, but only to
    # a caller that sent Recv-Info (RFC 6086 section 5.2.3).
    if call.get_header("Recv-Info") is not None:
        reply.set_header("Recv-Info", PACKAGE)


@b2bua.on_info
async def on_info(call, request, leg):
    package = request.get_header("Info-Package")
    if package is None:
        return                       # DTMF and other INFO usages: relayed as before

    if call.state != "answered":
        request.reply(403, "Forbidden")
        return

    if package != PACKAGE:
        request.set_reply_header("Recv-Info", PACKAGE)
        request.reply(469, "Bad Info Package")
        return

    request.reply(200, "OK")         # no body: package data is not sent in a response
    asyncio.create_task(push_state(call.call_id, leg, request.body))


async def push_state(call_id, leg, received):
    status = await b2bua.send_info(
        call_id,
        b'{"state": "active"}',
        CONTENT_TYPE,
        headers={"Info-Package": PACKAGE, "Content-Disposition": "Info-Package"},
        leg=leg,                     # back to the party that sent the INFO
        timeout_ms=5000,
    )
    # status is the final status code, or None if none arrived in time.
```

### Advertising on the other paths

- **A call siphon answers itself** (no far leg): put it on the answer,
  `call.answer(200, "OK", body=sdp, content_type="application/sdp",
  headers={"Recv-Info": PACKAGE})`. As above, only when the INVITE carried
  `Recv-Info`. `Recv-Info` is not one of the headers siphon owns on that 2xx.
- **An INVITE siphon sends toward a subscriber**: the script is the UAC of that
  leg and so includes `Recv-Info` itself. `call.set_header("Recv-Info",
  PACKAGE)` before `call.dial(...)`, or `headers={"Recv-Info": PACKAGE}` on
  `b2bua.originate()`. Leave the `strip=` off that dial, or it removes it.
- **Reading what the other party advertised**: for the caller,
  `advertised(call.get_header("Recv-Info"))` in `on_invite` (the first
  `Recv-Info` header; a UA may use several). For the callee,
  `advertised(reply.get_header("Recv-Info"))` in `@b2bua.on_answer`. Check the
  package is in the list before `send_info` to that party.

### What each branch of `on_info` does

| INFO | Answer | Relayed to the other leg |
|---|---|---|
| No `Info-Package` (DTMF, legacy usages) | the handler leaves it | yes (a call with one leg: a bare 200) |
| `Info-Package` before the call is answered | `403` | no |
| An unadvertised package | `469` with `Recv-Info: example-package` | no |
| `example-package` | `200`, then a task sends the state INFO | no |

A DTMF INFO is also surfaced to `@rtpengine.on_dtmf`, whichever way it goes.

## Notes

- **The answer goes out when the handler returns.** `asyncio.create_task` starts
  the follow-up work and returns at once; the task sends its INFO after the 200.
- **`leg`** says which party sent the INFO, `"caller"` or `"callee"`, and is
  what `send_info(leg=)` takes. It also holds under `call.keep_call_id()`.
- **`b2bua.send_info` takes the SIP Call-ID** (`call.call_id`). Read it before
  starting the task rather than holding the `call` object across awaits.
- **Test it** without a server: `SipTestHarness.send_info(headers={"Info-Package":
  ...}, leg=...)` delivers an INFO to the handlers and returns the answer; see
  [Call](../reference/call.md).
