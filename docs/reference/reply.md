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

`@proxy.on_reply("INVITE")` / `@proxy.on_reply("INVITE|UPDATE")` narrows a
handler to responses to those request methods, the same filter shape as
`@proxy.on_request`. Filtered and unfiltered handlers all run, in registration
order, and a response no handler matches is forwarded unchanged.
`@proxy.on_register_reply` is shorthand for `@proxy.on_reply("REGISTER")`.

::: siphon_sdk.reply.Reply
