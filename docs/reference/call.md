# Call

The `Call` object drives a back-to-back user agent (B2BUA). Unlike the proxy
`Request`, a `Call` owns both legs — it can dial, fork, bridge, rewrite either
leg's URIs, and anchor media. It is passed to the `@b2bua.*` handlers.

```python
from siphon import b2bua

@b2bua.on_invite
async def bridge(call):
    call.dial(call.ruri)
```

::: siphon_sdk.call.Call

## Placing a call: `b2bua.originate`

Every handler above is driven by a call that arrived. `b2bua.originate()` creates
one from nothing — click-to-dial, callbacks, outbound notification — so it works
from a timer or an event callback, where no `Call` object exists at all.

It returns as soon as the INVITE is on the wire, with the new leg's SIP Call-ID;
it does **not** wait for the callee. Ringing and answer come back through the
ordinary handlers (`@b2bua.on_answer`, `@b2bua.on_failure`, `@b2bua.on_bye`), and
the returned Call-ID is the handle for `b2bua.terminate()` / `b2bua.refer()`.

```python
from siphon import b2bua, timer

@timer.every(seconds=60)
def reminders():
    for number in due_numbers():
        b2bua.originate(
            to=f"sip:{number}@carrier.example",
            from_uri="sip:+14035550100@siphon.example",
            from_display="Reminders",
            media=True,          # siphon anchors the leg on the media backend
            timeout=30,          # CANCELled if nobody answers in 30 s
        )
```

Exactly one media plan is required — an INVITE with no offer and no way to answer
the callee's would connect a call with no audio: `sdp=` (your own offer, any
backend) or `media=True` (siphon anchors it; `siphon-rtp` backend). The full
argument set and its failure modes are below; the out-of-process twin is the
control plane's [`originate` verb](control-plane.md#placing-a-call-originate).

::: siphon_sdk.mock_module.MockB2bua.originate

## Joining two calls: `b2bua.bridge`

`b2bua.originate` gives a script a second call; `b2bua.bridge` connects it to the
first. Both legs are named by SIP Call-ID, so it works from a timer or an event
callback where no `Call` object exists.

The leg named first is the **anchor**: it keeps its media session, and the other
joins it. The call resolves once the media has been re-pointed and the first
re-INVITE is on the wire — a bridge is two RFC 3261 §14 re-INVITEs across two
dialogs, and the far ends' verdict arrives on the control rail as
`ChannelBridged` / `BridgeFailed`.

```python
from siphon import b2bua

@b2bua.on_answer
async def connect_the_supervisor(call):
    supervisor = b2bua.originate(
        to="sip:+15550142@example.com",
        media=True,                 # siphon anchors the leg
    )
    # ... wait for it to answer (a @b2bua.on_answer for that leg) ...
    await b2bua.bridge(call.call_id, supervisor, on_peer_hangup="hold")
```

`unbridge` parts them without ending either call: both legs stay answered, owned
and held (`a=sendonly`, RFC 3264 §8.4), so either can be bridged again or hung
up. Every refusal raises `ValueError` prefixed with a stable cause token rather
than returning a hollow success. The out-of-process twin is the control plane's
[`bridge` verb](control-plane.md#joining-two-legs-bridge).

::: siphon_sdk.mock_module.MockB2bua.bridge

::: siphon_sdk.mock_module.MockB2bua.unbridge

## Logging the outbound leg: `b2bua.log_dial`

A B2BUA call says nothing at `log.level: info` about where it dialled. The
obvious workaround is a `log.info()` next to the `call.dial()`, and it has a real
flaw: `call.dial()` does not dial. It records an action that the framework
executes once the handler returns, so the line is written before the dial exists
and still claims it when the destination fails to resolve. It also logs the
string the script passed, which is not necessarily what goes on the wire — the
header policy, the number policy, and LCR's tech-prefix / retarget / CLIR steps
all still get a turn.

Turn the framework's own line on instead:

```yaml
b2bua:
  log_dial: true      # default false
```

```
B2BUA: dialling B-leg  call_id=… b_leg_call_id=… ruri=sip:…@carrier.example
                       next_hop=Some("sip:198.51.100.7:5060")
                       destination=198.51.100.7:5060 transport=udp source=…
```

It is emitted from the send itself, so the R-URI is the one on the wire and
`b_leg_call_id` is the Call-ID the far end will quote back at you. It covers
every outbound INVITE — `call.dial()`, each `call.fork()` branch, each
`call.route()` carrier attempt, and a REFER-terminate re-dial — so there is no
per-call-site flag to forget on one of three dial paths.

It is off by default because it is one line per call on the busiest path siphon
has, which is an operator's decision rather than an upgrade's. (The
[LCR failover lines](../cookbook/least-cost-routing.md) log at `info`
unconditionally — they fire only when a carrier fails, not on every call.)

## `MediaHandle`

Returned by `call.media` — controls RTP anchoring for the call.

::: siphon_sdk.types.MediaHandle

## `ByeInitiator`

Identifies which side ended an answered call (surfaced on `@b2bua.on_bye`).

::: siphon_sdk.types.ByeInitiator
