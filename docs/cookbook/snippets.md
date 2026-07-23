# Quick recipes

Small, common building blocks. Each is a few lines you drop into a
`@proxy.on_request` (or B2BUA) handler. They use only documented primitives; the
fuller recipes ([proxy](proxy.md), [SBC](sbc.md),
[security](security.md)) show them in context.

## Block scanners silently

No response means no fingerprint for the scanner to learn from.

```python
import re
from siphon import proxy

SCANNERS = re.compile(r"sipvicious|friendly-scanner|sipcli", re.IGNORECASE)

@proxy.on_request
def guard(request):
    if SCANNERS.search(request.get_header("User-Agent") or ""):
        return                      # drop
    request.relay()
```

## Accept only from a trusted gateway

`from_gateway` is IP membership against a configured gateway group (a trust
signal on TLS/TCP, a direction hint on UDP). `source_ip_in` checks raw CIDRs.

```python
@proxy.on_request("INVITE")
def ingress(request):
    if not request.from_gateway("carriers"):
        request.reply(403, "Forbidden")
        return
    request.relay()
```

## Rate-limit per source

```python
@proxy.on_request("REGISTER")
def limit(request):
    # max 5 REGISTERs per 10s window from this source
    if not proxy.rate_limit(request, 10, 5):
        return                      # over budget: drop
    request.relay()
```

## Force a single codec

```python
from siphon import sdp

@proxy.on_request("INVITE")
def g711_only(request):
    if request.has_body("application/sdp"):
        s = sdp.parse(request)
        s.filter_codecs(["PCMU", "PCMA"])
        s.apply(request)
    request.relay()
```

## Prefix-route to a gateway

```python
from siphon import gateway

@proxy.on_request("INVITE")
def route(request):
    user = request.ruri.user or ""
    group = "emergency" if user in ("112", "911") else "carriers"
    destination = gateway.select(group, key=request.call_id)
    if not destination:
        request.reply(503, "Service Unavailable")
        return
    request.relay(destination.uri)
```

## Reject anonymous callers

```python
@proxy.on_request("INVITE")
def screen(request):
    from_uri = request.from_uri
    if from_uri and (from_uri.host == "anonymous.invalid"
                     or (from_uri.user or "").lower() == "anonymous"):
        request.reply(433, "Anonymity Disallowed")   # RFC 5079
        return
    request.relay()
```

## Send to voicemail when everything fails

`@proxy.on_failure` fires once all branches of a relay/fork have failed.

```python
@proxy.on_failure
def failover(request, reply):
    if request.method == "INVITE":
        request.relay(f"sip:vm-{request.ruri.user}@voicemail.example.net")
    else:
        reply.relay()               # forward the original failure
```

## See also

- [Stateful proxy](proxy.md) and [Hardening & security](security.md) put these together.
- [SIP & SDP manipulation](manipulation.md) for the full header/SDP surface.
- [Request reference](../reference/request.md) · [Proxy & B2BUA reference](../reference/proxy.md).
