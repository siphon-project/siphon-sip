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

A handler sees a request's responses until its final response has gone to the
caller. One response can still follow that: a 2xx to an INVITE from a branch
the proxy had already given up on (another fork branch answered first, the
request was rejected with `reply.reject()`, or the caller cancelled). RFC 3261
§16.7 has it forwarded to the caller, who ACKs it and ends that dialog with a
BYE, and siphon forwards it as it is: no `@proxy.on_reply` handler and no
per-relay `on_reply=` callback runs for it, and it is not the call's answer in
a CDR or on Rf.

The same holds for a retransmission of a 2xx to an INVITE. A handler sees the
first copy; the callee repeats it until the caller's ACK arrives, and siphon
forwards each repeat by its Via stack with the framework's own changes only
(its Via removed, the Contact fixed under `nat.fix_contact`). What a handler
changed on the first copy, a header or the SDP, is not on the repeats: they
exist to get an answer through that was lost, and the caller takes its dialog
from whichever copy arrives first.

::: siphon_sdk.reply.Reply
