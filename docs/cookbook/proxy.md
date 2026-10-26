# Stateful proxy

A proxy routes requests without taking part in the media or owning the dialog. This
recipe is a residential/edge proxy: it challenges REGISTER, routes calls to
registered contacts, loose-routes in-dialog traffic, and drops garbage before it
costs you anything.

## Script

```python
from siphon import proxy, registrar, auth, log

DOMAIN = "example.com"

@proxy.on_request
async def route(request):
    # 1. Drop malformed / torture traffic before any work (RFC 4475).
    #    Scoped to out-of-dialog requests; dropped silently so we don't
    #    fingerprint the server to scanners.
    if not request.in_dialog and not proxy.sanity_check(request):
        return

    # 2. Local OPTIONS keepalive.
    if request.method == "OPTIONS" and request.ruri.is_local and not request.ruri.user:
        request.reply(200, "OK")
        return

    # 3. In-dialog requests follow the dialog's route set.
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # 4. REGISTER.
    if request.method == "REGISTER":
        if not await auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)
        return

    # 5. Out-of-dialog INVITE/MESSAGE/…: location lookup + fork.
    if not request.ruri.user:
        request.reply(484, "Address Incomplete")
        return
    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return
    request.record_route()
    request.fork(contacts)
```

## The routing primitives

| Call | What it does |
|---|---|
| `request.relay()` / `request.relay("sip:next@host")` | Forward to the next hop (or an explicit target). Like Kamailio `t_relay()`. |
| `request.fork(targets, strategy="parallel"\|"sequential")` | Fork to many targets; first 2xx wins (parallel) or try in order (sequential). |
| `request.relay(..., no_response_ms=4000)` | Give up on a branch that sends no response at all within that time, as a `408` (see [below](#failing-over-from-a-next-hop-that-never-answers)). `fork()` takes it too. |
| `request.record_route()` | Insert this proxy into the dialog's route set so in-dialog requests come back. |
| `request.loose_route()` | Consume the top `Route` and route the request onward (RFC 3261 §16.12). |
| `request.reply(code, reason)` | Send a response from the proxy. |

The transaction layer handles CANCEL matching, Max-Forwards, retransmissions and
ACK-for-non-2xx automatically — you don't write routes for those.

## Aggregating fork results

For a parallel fork, SIPhon aggregates the branches per RFC 3261 §16.7. The first
2xx wins. When every branch fails, the caller gets one failure: a 6xx if there
is one, otherwise the lowest class present (3xx, then 4xx, then 5xx), with
401/407/415/420/484 preferred within 4xx. That branch's own response is
forwarded, a 401/407 carrying every other branch's challenge too, and a 503 is
sent as 500. To act when *all* branches fail:

```python
@proxy.on_failure
def failure_route(request, reply):
    # e.g. send to voicemail, or relay the best error upstream
    reply.relay()
```

`@proxy.on_failure` also fires for a plain single-destination `request.relay()`
— there is nothing to aggregate, so every non-2xx final response is "it failed".
The one exclusion is `487 Request Terminated`: the caller cancelled, and
re-targeting there would resurrect a call they have already abandoned (use
`@proxy.on_cancel` for that teardown).

The handler has three ways out. `reply.relay()` forwards the failure; a
`request.reply(code, reason)` answers with something else; and
`request.relay(...)` / `request.fork(...)` **re-targets** — a fresh attempt on
the same server transaction, so the caller keeps waiting on its original request
instead of seeing the error. Returning without any of them drops silently.
Re-targeting is bounded at 8 attempts per transaction (nothing in the protocol
bounds a chain of fresh client transactions), after which the failure is
forwarded.

## Failing over from a next hop that never answers

A branch whose next hop sends nothing back normally ends at Timer B (INVITE)
or Timer F (anything else): 32 s, then a `408` into `@proxy.on_failure`. That
is too slow when the script has somewhere else to go. `no_response_ms=` on
`relay()` or `fork()` ends the branch sooner:

```python
@proxy.on_request("INVITE")
def route(request):
    request.relay(next_hop, no_response_ms=4000)

@proxy.on_failure
def failure_route(request, reply):
    if reply.status_code == 408:
        request.relay(backup_hop, no_response_ms=4000)   # try the other one
    else:
        reply.relay()
```

This is the check an S-CSCF needs for HSS based P-CSCF restoration (3GPP TS
24.229 §5.4.3.3): a terminating request the P-CSCF does not answer at all
"within a configurable time", which NOTE 24 puts below Timer B and Timer F.

- **Only silence counts.** Any response stops the timer, a `100 Trying`
  included. An INVITE that rang and then went quiet is left to Timer C
  (`transaction.timer_c_secs`).
- **The failure is a Timer B / F failure.** The branch ends as a locally
  generated `408 Request Timeout` that goes through the same RFC 3261 §16.7
  handling: `@proxy.on_failure`, the relay's own `on_failure=`, fork
  aggregation. A parallel fork keeps waiting on its other branches, and a
  sequential fork moves straight on to the next target, which gets the same
  bound.
- **No CANCEL before a provisional.** RFC 3261 §9.1 does not allow one, so the
  INVITE is just no longer retransmitted. If the next hop answers late with a
  provisional, that provisional is sent the CANCEL and is not forwarded, and
  the final response that follows is ACKed and absorbed. A late 2xx is
  forwarded, as every 2xx is (§16.7 step 5).
- **The bound must be below the transaction timeout.** Below Timer B (32 s)
  for an INVITE, below Timer F (`transaction.timeout_secs`, else 32 s) for
  anything else. A value at or over it, zero, a negative one, or any value on
  an ACK raises `ValueError`. It is refused rather than clamped, so the
  number the script runs on is the number it wrote.
- The caller's CANCEL, or another fork branch answering first, stops the
  timer as well.

`fork()` takes `on_reply=` and `on_failure=` the way `relay()` does; for a fork
`on_failure` runs once, with the best failure, when every branch has failed.

And to touch responses on the way back (rewrite headers, strip internal info):

```python
@proxy.on_reply
def reply_route(request, reply):
    reply.remove_header("X-Internal-Trace")
    reply.relay()
```

## Test it

```bash
# register a contact, then place a call to it
python3 deploy/ha-demo/sipcli.py register 127.0.0.1 5060 bob 127.0.0.1 5080
python3 deploy/ha-demo/sipcli.py invite   127.0.0.1 5060 bob     # -> 1xx (routed)
```

## See also

- Real example: [`scripts/proxy_default.py`](https://github.com/siphon-project/siphon-sip/blob/main/scripts/proxy_default.py), [`examples/proxy_gateway.py`](https://github.com/siphon-project/siphon-sip/blob/main/examples/proxy_gateway.py).
- [Load balancer](load-balancer.md) — route to a backend pool instead of registered contacts.
- [Media & RTP](media-rtp.md) — anchor media on a proxy with RTPEngine.
- Coming from Kamailio/OpenSIPS? See the [migration guide](../migrating-from-kamailio-opensips.md).
