# Request

The `Request` object is passed to every `@proxy.on_request` handler. It gives
read access to the parsed SIP message and methods to reply, relay, fork, and
rewrite headers before forwarding.

```python
from siphon import proxy

@proxy.on_request("INVITE")
def route(request):
    if request.ruri.is_local:
        request.relay()
    else:
        request.reply(403, "Forbidden")
```

::: siphon_sdk.request.Request
