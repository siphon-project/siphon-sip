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

An application server that places a call on a user's or a service identity's
behalf hands it to its S-CSCF with `route=["<sip:orig@scscf.example.com;lr>"]`:
the entries go out as the INVITE's Route headers (and on its CANCEL and the ACK
of a failure), so the S-CSCF reads the session case from its own Route entry
(TS 24.229 §5.7.3). `next_hop` only says where the packet goes; with no
`next_hop` the INVITE goes to the topmost Route entry.

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

## Taking over a dialog an INVITE names: `call.take_over`

`replace_peer` is siphon deciding to swap a party out. The mirror is a new
INVITE asking to take one of siphon's dialogs over. With `Replaces` (RFC 3891)
siphon does that itself, behind `b2bua.accept_replaces`. Other headers name a
dialog for the same purpose, and there the script decides: an SCC AS anchoring
a call gets a new INVITE from the access transfer function on SRVCC, carrying
`Target-Dialog` (RFC 4538) and `Require: tdialog`, naming the SCC AS's dialog
with the UE (TS 24.237 §12.3.5).

`call.take_over(call_id, local_tag, remote_tag, reinvite=True, headers=None)` in
`@b2bua.on_invite` runs the same takeover as `Replaces`. Once the handler
returns, siphon answers the new INVITE `200` with the SDP the surviving party
last gave, BYEs the named dialog's party (closing its leg exactly as a
`Replaces` takeover does), keeps the surviving party's dialog, and
relays between the two from then on. `headers=` go on that `200`, checked as
`answer(headers=…)` checks them; TS 24.237 §6A.4.3A has the SCC AS put the remote
party's `P-Asserted-Identity`, `Feature-Caps`, `Accept` and `Recv-Info` there.

```python
from siphon import b2bua

@b2bua.on_invite
def on_invite(call):
    target = call.get_header("Target-Dialog")
    if target and "tdialog" in (call.get_header("Require") or "") and from_atcf(call):
        dialog_call_id, _, rest = target.partition(";")
        params = dict(p.strip().split("=", 1) for p in rest.split(";") if "=" in p)
        # Target-Dialog names the dialog as its recipient sees it
        # (RFC 4538 §3): local-tag is siphon's tag, remote-tag the far party's.
        call.take_over(dialog_call_id.strip(),
                       local_tag=params["local-tag"],
                       remote_tag=params["remote-tag"],
                       reinvite=False,
                       headers={"P-Asserted-Identity": remote_identity(call)})
        return
    call.dial(call.ruri)
```

The dialog is named as siphon holds it: its Call-ID, siphon's own tag on it,
and the far party's tag on it. Either leg of a call can be named.

- **The script authorises it.** It works whether or not `b2bua.accept_replaces`
  is set, because calling it is the decision that switch stands in for. Knowing
  a dialog's identifiers is no authority to end it (RFC 3891 §5, RFC 4538 §4),
  so check the request first: where it came from, `Require: tdialog`, and your
  own correlation of the session.
- **Same timing as `Replaces`.** It runs after the handler returns, in place of
  any routing. It is an action like `dial()`, so the last action of the handler
  wins: a later `reject()` or `dial()` replaces it. It cannot be combined with
  `answer()`, whose `2xx` is already on the wire (`ValueError` either way
  round). It supersedes a takeover a `Replaces` on the same INVITE asked for.
- **`reinvite`.** `True` re-INVITEs the surviving party with the new INVITE's
  offer, exactly as a `Replaces` takeover does (TS 24.237 §12.3.5 C a).
  `False` leaves it alone, for a new leg whose media is the old one's because an
  access gateway kept the ports (§12.3.5 C b); the new party is then answered
  with the survivor's SDP as it stands, direction included. `False` raises
  `ValueError` on a call siphon anchors on a media engine: the takeover moves
  the surviving party onto a new engine session, which only a re-INVITE can
  tell it. A script that anchors the INVITE after calling `take_over` gets the
  takeover refused `500` instead.
- **Refusals** go on the wire once the handler returns: `481` when no dialog of
  this node matches, `480` when the named dialog is still early (only confirmed
  dialogs are taken over; TS 24.237 §12.3.2.3 answers an access transfer it
  cannot associate with an established dialog `480`), `488` when the INVITE
  carries no offer, `420` for a required
  extension siphon does not honour. `tdialog` is honoured on this path.

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

## Headers on siphon's own responses: `headers=`

`call.progress()`, `call.answer()` and `call.reject()` send the caller a
response siphon builds itself, with no B-leg response behind it for a header
policy to shape. Each takes `headers=`, a `{name: value}` mapping put on that
response last, replacing anything siphon put there first (`Server`, say). The
typical use is an announcement or early-media server telling the caller's
network to pass the media its 183 opens (RFC 5009 §8):

```python
from siphon import b2bua, rtpengine

@b2bua.on_invite
async def announce(call):
    sdp = await rtpengine.answer_local(call, profile="announcement")
    call.progress(183, "Session Progress", body=sdp,
                  content_type="application/sdp",
                  headers={"P-Early-Media": "sendrecv"})
    await rtpengine.play_media(call, file="/prompts/closed.wav")
    call.reject(480, "Temporarily Unavailable",
                headers={"Reason": "SIP;cause=480", "Retry-After": "3600"})
```

A header siphon owns on the response raises `ValueError` naming it, and nothing
is sent:

| Headers | Why they are siphon's |
|---|---|
| Via, From, To, Call-ID, CSeq | copied from the INVITE, To with the dialog's tag (RFC 3261 §8.2.6.2) |
| Contact, Record-Route, Route, Max-Forwards | the caller's remote target and route set (§12.1.1) |
| Content-Length, Content-Type | the body framing; pass `content_type=` |
| RSeq, RAck, Require, Supported | `100rel`: a provisional to a caller that asked for it goes out reliably on siphon's `RSeq` (RFC 3262 §3) |
| Session-Expires, Min-SE | the session timer siphon negotiates on the 2xx (RFC 4028 §9) |

Compact forms (`k`, `m`, `l`, ...) count as their long names, and a value with
a line break or NUL is refused too. The control plane's `answer`, `ring`,
`progress` and `reject` verbs take the same `headers` object with the same
rules ([control plane](control-plane.md)).

## The Contact of siphon's own answer: `contact=`

The Contact stays siphon's to build, but a script that answers the call itself
can name the URI in it: `call.answer()` and `call.progress()` take `contact=`,
a SIP or SIPS URI, and `contact_params=`, its header parameters. It becomes the
dialog's local target, so the 2xx, an 18x, and every later request and
response siphon sends the caller in that dialog carry it (RFC 3261 §12.1.1),
and the caller's in-dialog requests are addressed to it. The URI must route
back to siphon through the dialog's route set.

The use it is made for is a conference focus. It answers an INVITE to its
factory URI with the URI of the conference it created as its Contact, with the
`isfocus` feature parameter (RFC 4579 §5.1); the caller learns the conference
URI there (§5.2), and refers the other parties to it:

```python
call.answer(200, "OK", body=sdp, content_type="application/sdp",
            contact=f"sip:{room}@conf.example.com", contact_params="isfocus")
```

A URI siphon would not put in a Contact (not SIP or SIPS, in angle brackets,
with anything after it) or a parameter that is not a `generic-param` (RFC 3261
§25.1) raises `ValueError`, and nothing is sent.

## Hold, resume and other re-offers: `@b2bua.on_reoffer`

A re-INVITE or an UPDATE (RFC 3311) from either party of a bridged call
renegotiates the session siphon relays between them, through the media engine
when the call is anchored. `@b2bua.on_reoffer` sees it before it is relayed,
and `@b2bua.on_reoffer_answered` once the offerer has its final response.
Both are called with `(call, offer)`.

It also sees an offer from the caller of a call the script answered itself
with SDP the media engine holds no session for, a conference seat
(`rtpengine.conference_join`) for one. There is no other party to relay to:
`offer.answer()` answers it from the seat's answer with the direction the
offer leaves (a hold, RFC 3264 §8.4), `offer.answer(sdp=…)` with the script's
own, and `offer.reject()` refuses it. A handler that leaves it alone gets what
siphon does without one: a refresh answered from the session in force, a
change refused `488`.

```python
from siphon import b2bua, rtpengine

@b2bua.on_reoffer
def hold(call, offer):
    # The caller holds the callee: answer the hold here, keep the callee on
    # the media engine, and leave the callee's dialog as it is.
    if offer.kind == "hold" and offer.side == "a":
        offer.answer()

@b2bua.on_reoffer_answered
async def held(call, offer):
    if offer.kind == "hold" and offer.side == "a" and offer.status_code == 200:
        await rtpengine.play_media(call, file="/srv/moh.wav",
                                   repeat="inf", wait=False)
    elif offer.kind == "resume" and offer.status_code == 200:
        await rtpengine.stop_media(call)
```

What the offer says:

| Attribute | |
|---|---|
| `offer.method` | `"INVITE"` or `"UPDATE"` |
| `offer.side` | `"a"` (caller) or `"b"` (callee), as `call.refer_side` |
| `offer.sdp` | the offer as sent; `None` for an offerless re-INVITE (the 2xx carries the other party's offer, RFC 3261 §14.1) |
| `offer.request` | the request, for its headers; a header or body set on it is on the relayed request |
| `offer.direction` | `sendrecv` / `sendonly` / `recvonly` / `inactive` over the streams not rejected; a `0.0.0.0` connection address receives nothing (RFC 3264 §8.4) |
| `offer.previous_direction` | the same for the description that party last gave on its dialog |
| `offer.kind` | `"hold"` (stops receiving, TS 24.610 §4.5.2), `"resume"`, `"refresh"` (same streams, addresses and directions, as an RFC 4028 refresh is, even one that repeats `sendonly` on a held call), `"change"` |
| `offer.early` | an UPDATE between early dialogs (RFC 3311 §5.1) |

What the handler can do with it:

- **Nothing**: the offer is relayed as without the hook.
- **`offer.reject(code, reason)`** (300-699): siphon answers the offerer and
  relays nothing; the session stays as it was.
- **`offer.answer(sdp=None)`**: siphon answers the offerer itself and relays
  nothing. Without `sdp` the answer is the session in force toward the
  offerer (what siphon last sent it, the media engine's ports on an anchored
  call) with the formats both list and the direction the offer leaves, so a
  `sendonly` hold is answered `recvonly` (RFC 3264 §6.1). The media engine is
  not told: a two-party session cannot be answered by the engine for one side
  alone, and keeping it as it is keeps the other party's media on the engine,
  where `rtpengine.play_media` reaches it. An offerless re-INVITE gets that
  session as siphon's offer. Streams that are keyed, use ICE or are grouped
  cannot be answered this way and are refused `488`. With `sdp`, that SDP is
  the answer. siphon puts its own `o=` on either (RFC 3264 §8).

Every request is answered. A handler that raises, or an async one that runs
past `script.handler_timeout_secs`, decides nothing and the offer is relayed.
A crossing offer is answered `491 Request Pending` (RFC 3261 §14.1) before the
script would see it. Not shown: a call siphon answered itself (no second
party) and a leg of a controller bridge.

`@b2bua.on_reoffer_answered` adds `offer.status_code`, `offer.answer_sdp` (as
the offerer was sent it), `offer.answer_direction` and
`offer.answered_locally`, which is true when siphon answered: the script's
`reject()` or `answer()`, or a media engine that would not take the offer.
It is a notification; a raise there changes nothing.

In the SDK, `SipTestHarness.send_reoffer()` and `send_reoffer_answered()`
drive both handlers:

::: siphon_sdk.reoffer.Reoffer

## `MediaHandle`

Returned by `call.media` — controls RTP anchoring for the call.

::: siphon_sdk.types.MediaHandle

## `ByeInitiator`

Identifies which side ended an answered call (surfaced on `@b2bua.on_bye`).

::: siphon_sdk.types.ByeInitiator
