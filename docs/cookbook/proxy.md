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
def route(request):
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
        if not auth.require_digest(request, realm=DOMAIN):
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
| `request.record_route()` | Insert this proxy into the dialog's route set so in-dialog requests come back. |
| `request.loose_route()` | Consume the top `Route` and route the request onward (RFC 3261 §16.12). |
| `request.reply(code, reason)` | Send a response from the proxy. |

The transaction layer handles CANCEL matching, Max-Forwards, retransmissions and
ACK-for-non-2xx automatically — you don't write routes for those.

## Aggregating fork results

For a parallel fork, SIPhon aggregates the branches per RFC 3261 §16.7 (first 2xx
wins, best error otherwise). To act when *all* branches fail:

```python
@proxy.on_failure
def failure_route(request, reply):
    # e.g. send to voicemail, or relay the best error upstream
    reply.relay()
```

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
