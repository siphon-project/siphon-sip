# Reply

The `Reply` object wraps a SIP response. It reaches your script in a
`@proxy.on_reply` handler (every response on a relayed transaction) and in a
`@proxy.on_failure` handler (the best error after all branches failed).

```python
from siphon import proxy

@proxy.on_reply
def observe(request, reply):
    if reply.status_code == 200 and request.method == "INVITE":
        reply.set_header("X-Answered-By", "siphon")
    reply.relay()
```

::: siphon_sdk.reply.Reply
