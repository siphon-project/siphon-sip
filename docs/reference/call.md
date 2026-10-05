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
backend), `body=` + `content_type=` (the same slot with the type spelled out,
for an offer travelling inside a `multipart/*` body per RFC 5621 §3), or
`media=True` (siphon anchors it; `siphon-rtp` backend). Whichever spelling, the
body has to carry an SDP offer — a body that carries none raises rather than
placing a call the callee can only answer by offering into silence. The full
argument set and its failure modes are below; the out-of-process twin is the
control plane's [`originate` verb](control-plane.md#placing-a-call-originate).

A placed call runs the RFC 4028 session timer of the `session_timer:` block, or
the one `session_timer={"expires": 1800, "min_se": 90, "refresher": "b2bua"}`
sets on it (keys left out default as in `call.session_timer()`). The INVITE asks
for it, the callee's 2xx says who refreshes, and siphon refreshes the dialog or
releases the call just before a session the callee let run out expires.

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

## Swapping a party mid-call: `b2bua.replace_peer`

`bridge` joins two calls the script owns. `replace_peer` does something
different: it takes one answered call and swaps out one of its two parties for
somebody new, without either party's endpoint asking for it.

This is the transfer siphon already runs when it terminates an inbound REFER
(`call.accept_refer(mode="terminate")`), reachable when *siphon* is the one
deciding. It dials the target as a new leg on the same call, re-anchors the
surviving party's media onto it, and once the target answers promotes it into
the surviving pair and BYEs the leg it replaced. An IVR that has worked out
where the caller should go, a supervisor take-over, a controller handing a call
from an AI to a human.

The obvious hand-rolled version — hang up one leg, then re-INVITE the other with
new SDP — is worse in two ways that only show up in production. The caller hears
dead air for the whole ring, because the leg is gone before the target has even
been dialled. And the call's own state is left behind: no `@b2bua.on_bye`, no
CDR, no charging stop, no media release, and a later `terminate` re-BYEs a
dialog that is already dead. `replace_peer` keeps the replaced leg up until the
target answers and releases it through the real teardown.

```python
from siphon import b2bua, rtpengine

@rtpengine.on_dtmf
def zero_for_an_operator(call_id, from_tag, digit, duration_ms, volume):
    if digit == "0":
        # The caller stays connected to the IVR while the operator's phone
        # rings; if nobody picks up in 45s the call is left exactly as it was.
        b2bua.replace_peer(call_id, "sip:operator@pbx.example", timeout=45)
```

Every refusal raises `ValueError` prefixed with a stable cause token — a caller
that cannot tell a refused replacement from a started one will tear down a call
that is still up. The out-of-process twin is the control plane's
[`replace_peer` verb](control-plane.md#swapping-a-party-replace_peer).

::: siphon_sdk.mock_module.MockB2bua.replace_peer

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

## Bounding a call: `timeout` and `max_duration`

A call has two clocks, and they measure different things.

`timeout=` bounds the **ring**. If nothing answers in that many seconds siphon
CANCELs the outstanding legs and fires `@b2bua.on_failure` with `408`. Unless
the handler routes the call somewhere else or rejects it with a response of its
own, the caller gets that `408`. On a `call.fork()` where another branch already
failed with something that outranks a timeout (a `486`, say), the caller gets
that failure instead (RFC 3261 §16.7, §16.8). It stops mattering the moment a
`2xx` lands.

On `call.route()` each carrier has its own timer, and it bounds the wait for
that carrier to show progress (a 101-199) rather than for its answer. A carrier
that has rung keeps the call up to `timeout=`, then the call fails with `408`
instead of going to the next carrier. A sequence that ends on the ring timeout
of a carrier that never sent a 101-199 fails with `503` instead, and
`@b2bua.on_failure` gets `503`: no carrier reached the callee. So does a
sequence that moves on and finds none of the carriers left can be dialled,
whatever the carrier before them did. See
[ring timeout and progress](../cookbook/least-cost-routing.md#ring-timeout-and-progress).

`max_duration=` bounds the **talk**. The clock starts at the answer, so a call
that rang for 25 seconds still gets its full talk time. When it expires siphon
BYEs both legs.

```python
@b2bua.on_invite
def route(call):
    # 30s to answer, then at most an hour connected.
    call.dial(call.ruri, timeout=30, max_duration=3600)
```

Before this existed, an answered call was bounded by nothing but a peer BYE, a
script `terminate()`, or an RFC 4028 session timer where one is configured *and*
the far end honours it. A carrier leg that goes silent with its dialog still up
holds a call actor, a media anchor, a charging session and an RTP port pair for
as long as the process lives.

The operator backstop is the same cap applied to every call that does not ask
for its own:

```yaml
b2bua:
  max_call_duration_secs: 14400    # 4h; unset means uncapped
```

A call overrides it with `max_duration=<seconds>` and opts out of it entirely
with `max_duration=0`. The kwarg is on `call.dial()`, `call.fork()` and
`call.route()`; on a fork or an LCR sequence it is per *call*, not per branch or
per carrier — `timeout` bounds each attempt's ring, but whichever one answers
hands over a single answered call. A call that never dials at all — a UAS-mode
`call.answer()`, a `call.handover()` — reaches the same knob through
`call.set_max_duration(seconds)`.

On expiry siphon runs the ordinary teardown: a BYE to each leg carrying
`Reason: Q.850;cause=102;text="Maximum call duration exceeded"` (RFC 3326), a
CDR with `disconnect_initiator="timeout"`, Rf/Ro `ACR-STOP`, media released,
`StasisEnd` on the control rail. **No Python handler fires** — `@b2bua.on_bye`
reports which *peer* hung up, and here neither did, which is also how a
session-timer expiry and `call.terminate()` behave. The CDR is the record; its
`sip_reason` is what distinguishes a duration cut from a session-timer one.

One more timer ends an answered call the same way. siphon retransmits every 2xx
it sends the caller, relayed or its own `call.answer()`, until the caller's ACK
arrives. If none has arrived after 64×T1 (32 s), RFC 3261 §13.3.1.4 has the
session ended, and siphon sends both legs a BYE with
`Reason: Q.850;cause=102;text="No ACK received"`, through the same teardown and
with the same CDR `disconnect_initiator="timeout"`. An ACK that siphon processes
before the teardown runs keeps the call up.

A call that ends while its 2xx is still waiting for that ACK (the callee hangs
up right after answering, or any of the teardowns above) sends the callee its BYE
at once, but not the caller: RFC 3261 §15 sends no BYE on a dialog before its 2xx
is ACKed. The caller keeps receiving the 2xx, and its BYE goes out right after
its ACK, or at 64×T1 if the ACK never comes. The CDR, charging and media are
closed when the call ends, not when that BYE goes out.

::: siphon_sdk.call.Call.set_max_duration

## Limiting inbound calls: `b2bua.inbound_limit`

A B2BUA instance accepts every call it is sent unless told otherwise.
`b2bua.inbound_limit` puts a ceiling on that, so there is a number to plan
capacity against:

```yaml
b2bua:
  inbound_limit:
    max_concurrent_calls: 20000   # calls held at once
    max_calls_per_second: 500     # new calls, with a burst of one second's worth
    reject_code: 503              # default
    retry_after_secs: 1           # default; 0 omits Retry-After
```

Both ceilings are unset by default, and `0` means unlimited.

The check runs on the inbound initial INVITE **before `@b2bua.on_invite`**. A
call past either ceiling is answered by siphon: `503 Service Unavailable` with
`Retry-After` (RFC 3261 §21.5.4), or whatever `reject_code` names. **No handler
fires for a refused call.** There is no `Call`, so nothing for a script to log
or re-route. Two things record it:

- a CDR with `disconnect_initiator="local"`, the refusal's status in
  `response_code`, and `refusal_scope` / `refusal_reason` (`concurrent` or
  `rate`) flattened in beside the fixed fields;
- `siphon_b2bua_inbound_calls_refused_total{reason}`.

Only inbound calls are refused. These still take a slot, so
`max_concurrent_calls` stays the number of calls the instance is carrying, but
are never turned away:

- a call siphon places itself (`b2bua.originate`, the control plane);
- an emergency call, whose request URI is `urn:service:sos` or a sub-service
  of it (RFC 5031). An emergency number dialled as a `sip:` URI is not
  recognised;
- an INVITE taking over a dialog with `Replaces` (RFC 3891).

What to size the ceilings by:

- **`max_calls_per_second` counts INVITEs.** A call the script challenges with
  `auth.require_proxy_digest()` arrives twice, the challenged INVITE and the
  retry carrying credentials, so it spends two.
- **The ceilings are per instance.** N nodes behind a load balancer accept N
  times what is configured.
- **A 503 moves traffic.** Many peers read it as "this server is down" and send
  everything elsewhere, for `Retry-After` seconds if the header is there. That is
  what an overloaded instance wants. `reject_code: 486` or `480` is gentler.
- **The source address is not checked.** Any caller can claim the emergency
  exemption by addressing `urn:service:sos`.

The limits are published as gauges (`0` = unlimited), so utilisation is one
division: `siphon_b2bua_calls_active / siphon_b2bua_max_concurrent_calls`.

### Limiting one carrier: `gateway.groups[].inbound_limit`

The same block on a gateway group caps the calls arriving **from** that group:

```yaml
gateway:
  groups:
    - name: "carrier-a"
      source_networks: ["203.0.113.0/24"]
      inbound_limit:
        max_concurrent_calls: 300
        max_calls_per_second: 30
        reject_code: 486
      destinations:
        - uri: "sip:gw1.carrier.example:5060"
```

A caller belongs to a group when its source address is one the group admits:
an address its destinations resolve to, or one inside `source_networks`. That
is the membership `call.from_gateway()` answers from. Calls siphon sends *to*
the group are not counted.

Everything above holds for a group's limit too, with these differences:

- **The group is judged first.** A carrier over its own limit is answered with
  its group's `reject_code` and `retry_after_secs`, and takes nothing from the
  instance. A carrier inside its own limit is still held to
  `b2bua.inbound_limit`, and that refusal is the instance's.
- **A source two limited groups admit is counted against both**, and refused by
  whichever is full.
- **The CDR names the group**: `refusal_scope` is `gateway` and `gateway_group`
  is the group's name. The counter is
  `siphon_gateway_inbound_calls_refused_total{group,reason}`, and
  `siphon_gateway_inbound_calls_active{group}` over
  `siphon_gateway_inbound_max_concurrent_calls{group}` is the carrier's
  utilisation. `GET /admin/gateways` reports the same under `inbound_limit`.
- **On UDP the source address can be forged**, so a third party can spend a
  carrier's budget by sending from its address. Over TCP and TLS it cannot.
- **A changed limit applies to the calls already up.** The count belongs to the
  group's name, so reloading a provisioned group does not restart it.

Groups a script adds with `gateway.add_group()` cannot carry a limit. A group
provisioned through `gateway.backend` can: see
[the provisioning contract](gateway-api.md#inbound-limit).

A retransmission of a refused INVITE is answered with the same response and is
not counted again (RFC 3261 §17.2.1). A new attempt, which carries a new Via
branch, is admitted or refused on its own.

Test a script against a limit with
`SipTestHarness.set_inbound_limit()`:

::: siphon_sdk.testing.SipTestHarness.set_inbound_limit

## `MediaHandle`

Returned by `call.media` — controls RTP anchoring for the call.

::: siphon_sdk.types.MediaHandle

## `ByeInitiator`

Identifies which side ended an answered call (surfaced on `@b2bua.on_bye`).

::: siphon_sdk.types.ByeInitiator
