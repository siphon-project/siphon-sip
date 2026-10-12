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

## A callee's provisional in a B2BUA script

In `@b2bua.on_provisional` and `@b2bua.on_early_media` the `Reply` is a
provisional response of the callee that SIPhon is about to relay to the caller.
It is relayed whether or not the handler calls `reply.relay()`, and the handler
may decide what the caller is sent of it:

| Call | The caller is sent |
|---|---|
| nothing, or `reply.relay()` | the response as it is |
| `reply.relay(body=False)` | the response without its body |
| `reply.withhold()` | nothing for this response |

The last call decides. `reply.has_body("application/sdp")` says whether the
response carries a session description and `reply.get_header("P-Early-Media")`
returns the callee's early media authorisation (RFC 5009), or `None`.

Only the caller's side changes. The callee's provisional is PRACKed when it was
reliable, `@b2bua.on_early_media` still runs with the body in place, and a
session description kept from the caller is the answer the caller has not had,
so the 2xx carries it even when the callee's own 2xx has none (RFC 3261
§13.2.1). Toward a caller that uses `100rel`, a provisional relayed without its
body is still sent reliably when the callee's was, on SIPhon's own `RSeq`, and
a withheld one takes no `RSeq` (RFC 3262 §3).

On any other reply (`@proxy.on_reply`, `@proxy.on_failure`,
`@b2bua.on_answer`) `reply.relay(body=False)` and `reply.withhold()` raise
`RuntimeError`: nothing there would carry the decision out. The
[SBC cookbook](../cookbook/sbc.md#ringback-toward-the-calling-network) has the
recipe these exist for.

::: siphon_sdk.reply.Reply
