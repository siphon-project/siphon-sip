# Control plane (remote SDKs)

SIPhon's B2BUA can hand a live call to an **out-of-process application** over a
WebSocket, the model Asterisk gives you with ARI and FreeSWITCH with ESL. A
script hands a call over with `call.handover("app")`; siphon holds the INVITE
un-dialed, emits a `StasisStart` carrying the full SIP context, and your
application answers, progresses, rejects, hangs up, refers, or reads and writes
per-call variables over the socket.

The **client SDKs are the supported way to build that application.** They hide
the wire — no hand-rolled JSON, no request-id bookkeeping, no reconnect loop —
and they are versioned against the `siphon-control.v1` protocol independently of
the siphon server, so a controller you write today keeps working across siphon
upgrades. Reach for the raw protocol only when you need a client in a language
the SDKs don't cover.

| You want to… | Use |
| --- | --- |
| Build a controller in **Python** | `pip install siphon-control` |
| Build a controller in **Rust** | `cargo add siphon-control-client` |
| Build a controller in **TypeScript** | `npm i @siphon-project/control` |
| Build a controller in **another language** | the [raw `siphon-control.v1` protocol](#under-the-hood-the-raw-protocol) |

## Python — `siphon-control`

```bash
pip install siphon-control
```

A native (PyO3) extension over the async Rust client. The wheel is published
for both GIL and free-threaded CPython 3.14, so it drops into a plain
interpreter or the free-threaded runtime siphon itself uses.

```python
import asyncio
from siphon_control import ControlClient, ControlError

client = ControlClient(app="ivr-app", token="s3cr3t",
                       url="ws://siphon:9090/control/ws")

@client.on_call
async def handle(call):
    await call.answer()                       # UAS 2xx to the parked A-leg
    try:
        await call.transfer("sip:agent@pbx")  # REFER; awaits the correlated reply
    except ControlError as error:
        print("transfer rejected:", error.code)  # stable code: not_found, forbidden, …
    await call.hangup()

asyncio.run(client.run())                     # connect, dispatch, reconnect + resync
```

`Call` verbs: `answer()` / `answer_with(code, …)`, `progress()`,
`reject(code, reason)`, `hangup(reason=None)`, `refer(to)` / `transfer(to)`,
`set_header(name, value)` / `get_header(name)`, `set_var(key, value)` /
`get_var(key)`, plus the generic `command(verb, args=None)` escape hatch and
`next_event()`. A rejected command raises `ControlError` carrying a stable
`.code`. Media verbs (`play_file` / `dtmf`) raise with `code ==
"unsupported_verb"` until the server implements them.

## Rust — `siphon-control-client`

```bash
cargo add siphon-control-client
```

```rust
use siphon_control_client::{ClientConfig, sip::SipClient};

# async fn demo() -> Result<(), siphon_control_client::ControlError> {
let client = SipClient::connect(
    ClientConfig::new("ws://siphon:9090/control/ws", "ivr-app", "s3cr3t"),
)
.await?;

client
    .on_call(|call| async move {
        call.answer().await?;
        call.transfer("sip:agent@pbx").await
    })
    .await?;
# Ok(())
# }
```

The client splits into a protocol-agnostic core (`ControlClient` /
`ControlServer` — transport, `hello`, request-id correlation, reconnect +
`resync`, and a generic `command(module, verb, target, args)` primitive that
works for any adapter) and a typed `sip` facade (`sip::Call`) layered on top. A
rejected command maps to `ControlError::Command` carrying the stable
`ControlErrorCode`.

## TypeScript — `@siphon-project/control`

```bash
npm i @siphon-project/control
```

```typescript
import { SipClient, ControlError } from "@siphon-project/control";

const client = await SipClient.connect({
  url: "ws://siphon:9090/control/ws",
  app: "ivr-app",
  token: "s3cr3t",
});

await client.onCall(async (call) => {
  await call.answer();                        // UAS 2xx to the parked A-leg
  try {
    await call.transfer("sip:agent@pbx");     // REFER; awaits the correlated reply
  } catch (error) {
    if (error instanceof ControlError) {
      console.log("transfer rejected:", error.code);  // stable code
    }
  }
  await call.hangup();
});                                            // connect, dispatch, reconnect + resync
```

The same `Call` verbs as the Python and Rust facades. `SipClient` / `SipServer`
are the SIP facade over the generic `ControlClient` / `ControlServer` core; both
expose `onCall(handler)` and the identical `Call` handle — `SipServer` is the
per-call-connect twin (siphon dials the app).

## Connection modes

All three SDKs support the two modes, over the same JSON-over-WebSocket protocol.

- **Outbound per-call-connect (the multi-pod default).** Your app runs a
  WebSocket server; siphon dials it once per handed-over call and the accepting
  socket owns that call (the FreeSWITCH-outbound model). Siphon always dials
  *out*, so the "which pod owns the call" affinity problem never arises. There
  is no `hello` — the first frame is `StasisStart`.
- **Inbound persistent.** Your app connects in to `control.listen` and owns
  calls assigned to it (round-robin across the app's connections). It sends a
  first `hello` and can `resync` to re-attach its calls after a reconnect.

## Handing a call over

Handover happens in the in-process B2BUA script (the
[`call.handover`](call.md) verb), not in the controller:

```python
from siphon import b2bua

@b2bua.on_invite
async def route(call):
    if call.to_uri.endswith("@ivr.example.com"):
        call.handover("ivr-app")                 # park + hand to the controller
    elif call.to_uri.endswith("@ai.example.com"):
        call.handover("ivr-app", answer=True,    # answer-first (AI-park):
                      ws_uri="wss://ai.example/stream/{call_id}")
    else:
        call.dial(call.ruri)                     # ordinary B2BUA
```

`answer=True` (answer-first / AI-park) answers the call and anchors its media to
a WebSocket bridge before handing over, so the controller drives an
already-connected channel; it requires the `siphon-rtp` media backend.

## siphon configuration

```yaml
control:
  # outbound per-call-connect (default) — siphon dials the app per call:
  apps:
    - name: "ivr-app"
      token: "${IVR_APP_TOKEN}"
      per_call_connect: true
      connect_url: "ws://127.0.0.1:8443/siphon"
  # inbound persistent — the app connects in here instead:
  # listen: "127.0.0.1:9092"
  limits:
    event_queue_depth: 1024
    reattach_grace_secs: 10
```

Per-app bearer tokens are constant-time compared and feed the existing auto-ban
store. Dispatch is exactly-one-owner with per-tenant scoping: a command against
another app's call returns `forbidden`, and a command against a dead or unknown
call returns `not_found` — neither ever hangs.

## Under the hood: the raw protocol

The SDKs speak `siphon-control.v1`: a single WebSocket per connection, JSON text
frames, request-id correlated. You only need this layer to build a client in a
language the SDKs don't cover — otherwise the SDKs handle all of it.

```
command  (client → siphon)  { "id":"c-1", "type":"command", "module":"sip",
                              "verb":"answer", "target":{"channel":"<id>"},
                              "args":{"code":200} }
reply    (siphon → client)  { "id":"c-1", "type":"reply", "status":"ok",
                              "result":{...} }   // or "status":"error", "error":{code,message}
event    (siphon → client)  { "type":"event", "event":"StasisStart",
                              "channel":"<id>", "call_id":"<uuid>",
                              "sip_call_id":"<cid>", "payload":{...} }
```

Every event carries the stable id triple `{channel, call_id, sip_call_id}` —
`sip_call_id` is byte-identical to the CDR `call_id` and the HEP correlation
chunk, so logs join Homer and billing with no mapping table.

### Phase-1 verb set

| verb | module | args | notes |
|---|---|---|---|
| `originate` | sip | `{channel, to, from?, from_display?, to_display?, next_hop?, p_asserted_identity?, privacy?, headers?, sdp \| media, profile?, ws_uri?, timeout?, on_lost?, vars?}` | place an outbound call under a **caller-supplied** channel id; returns as soon as the INVITE is on the wire |
| `answer` | sip | `{code, reason?, body?, content_type?}` | UAS 2xx to the parked A-leg |
| `progress` | sip | `{code, reason?, body?, content_type?}` | 1xx / early media |
| `reject` | sip | `{code, reason?}` | final non-2xx + tear down |
| `hangup` | sip | `{reason?}` | BYE an answered call, or reject an unanswered one |
| `refer` | sip | `{to, replaces?}` | in-dialog REFER on the A-leg |
| `accept_refer` | sip | `{target?, next_hop?, mode?}` | accept a pending inbound REFER (from a `TransferRequested` event) and run the transfer |
| `reject_refer` | sip | `{code?, reason?}` | reject a pending inbound REFER with a final non-2xx (default `603 Decline`) |
| `route` | sip | `{targets, strategy?, headers?}` | return control to siphon: un-park the call and dial the B-leg via LCR sequential failover |
| `set_header` / `remove_header` / `get_header` | sip | `{name, value?}` | on the stored A-leg INVITE |
| `play` | sip | `{file\|db_id\|blob, repeat?, start_ms?, duration_ms?, to_tag?}` | play an announcement on the A-leg media (fire-and-forget) |
| `stop` | sip | — | stop the announcement currently playing |
| `dtmf` | sip | `{digits, duration_ms?, volume_dbm0?, pause_ms?, to_tag?}` | inject DTMF digits toward the A-leg |
| `hold` / `unhold` | sip | — | media hold via silence |
| `stream_start` | sip | `{ws_uri, direction?, channels?}` | attach a WebSocket audio tee (siphon-rtp backend only) |
| `stream_stop` | sip | — | detach the WebSocket audio tee |
| `set_var` / `get_var` | — | `{key, value?}` | per-call variables (drain with the call) |
| `resync` | — | — | re-attach + enumerate this app's owned calls |
| `describe` | — | — | list the registered adapters + their verb/event schema |

`route` is the consult-and-return flow: an app parks a call (deferred handover),
decides routing out-of-process (LCR / rating / business logic), then hands
control back to siphon with the decision. `targets` is a non-empty array of
either bare URI strings or objects `{uri, next_hop?, headers?, timeout?}`;
`strategy` defaults to `"sequential"` (v1 runs the LCR sequential-failover
engine only, so anything else is a typed `unsupported_verb`, never a silent
sequential); `headers` is an optional object applied to every attempt's B-leg
INVITE. On success siphon replies `{state: "routing", targets: N}`, emits a
`StasisEnd{reason: "routed"}` on the owning connection (control returned, the
call lives on), then owns the call: it dials the first carrier and advances
through the rest on reject/timeout, with `@b2bua.on_failure` handling carrier
failover. `continue` (bare hand-back, siphon re-decides routing through the
script's `@b2bua.on_*` handlers) is a follow-up, pending the control-loss
`fallback` re-dispatch path.

The media verbs (`play` / `stop` / `dtmf` / `hold` / `unhold` / `stream_start` /
`stream_stop`) act on the controlled A-leg's anchored media session. They are
resolved against the configured media backend and answer with a typed reply the
same way every other verb does — never a hang:

- `play` is **fire-and-forget**: the reply confirms the backend *accepted* the
  command (`{state: "playing"}`), it does not wait for the prompt to finish. The
  source is exactly one of `file` (a path on the media host), `db_id` (a prompt
  in the engine's DB), or `blob` (base64-encoded audio, since the wire is JSON).
- `hold` maps to the engine's *silence* (comfort-noise) mode and `unhold`
  restores it — a gentle hold that keeps the media path up. Dropping packets
  outright (`block`/`unblock`) is a separate future gate verb.
- `stream_start` / `stream_stop` attach and detach a **WebSocket audio tee** —
  an *additive* copy of the live call's audio for transcription / agent-assist /
  compliance, not a takeover of the media path. This is a `siphon-rtp`-backend
  feature: on rtpengine / rtpproxy it answers `unsupported_verb` rather than a
  hollow success. `direction` is `both` (default) / `caller` / `callee`, and
  `channels` is `1` (mixed mono) or `2` (caller/callee stereo).
- A call with no anchored media session answers `not_found`; a backend that
  cannot perform the op answers `unsupported_verb`; any other backend failure
  answers `unavailable`.

Inbound in-band DTMF on a controlled call is pushed to the owning connection as
a `ChannelDtmfReceived` event, payload `{digit, duration_ms, volume, from_tag}`
(`from_tag` identifies which party pressed), so an IVR / AI app **collects digits
off the event stream** rather than through a blocking verb — there is
deliberately no server-side `collect_dtmf` (it would park an I/O worker). This is
additive to the in-process `@rtpengine.on_dtmf` dispatch: the digit fires both,
and it needs no extra configuration beyond the DTMF-log wiring the media engine
already uses.

An **inbound REFER on a controlled call** (a party asking to be transferred) is
handed to the owning app rather than the in-process `@b2bua.on_refer` path: siphon
holds the REFER un-answered and pushes a `TransferRequested` event, payload
`{refer_to, replaces?, from_tag}` (`replaces` present for an attended transfer;
`from_tag` identifies the referring party). The app decides with:

- `accept_refer` `{target?, next_hop?, mode?}` — run the transfer through siphon's
  shipped machinery. `target` overrides the Refer-To URI, `next_hop` steers egress
  without reshaping the R-URI, and `mode` is `terminate` (siphon-terminated: 202 +
  sipfrag NOTIFYs + re-dial the target as a new leg — the default, from
  `b2bua.default_refer_mode`) or `transparent` (forward the REFER on the far leg's
  own dialog). On a single-leg call (a voice-AI / IVR call siphon answered itself,
  no B leg) terminate mode re-dials the target off the A dialog.
- `reject_refer` `{code?, reason?}` — decline with a final non-2xx (default
  `603 Decline`).

If the app never decides, a decision deadline answers `603 Decline` (the same
default as when no `@b2bua.on_refer` handler is registered), so a REFER is never
left pending — the referrer is always answered (RFC 3515 §2.4.2). A bad `mode`
answers `bad_request`; a decision for a call with no pending REFER (already
decided, timed out, or gone) answers `not_found`. A REFER on an **uncontrolled**
call is unaffected — it still runs the Python `@b2bua.on_refer` path.

## Placing a call: `originate`

Every verb above acts on a call that already arrived. `originate` is the one that
creates one — the primitive under click-to-dial, callbacks, outbound
notification and the dial half of a transfer:

```json
{ "id":"c-7", "type":"command", "module":"sip", "verb":"originate",
  "args": { "channel": "cb-7f3a",
            "to": "sip:+15551000001@carrier.example",
            "from": "sip:+15550000001@example.com",
            "from_display": "Callback",
            "p_asserted_identity": "sip:+15550000001@example.com",
            "privacy": "allowed",
            "headers": { "X-Campaign": "reminder" },
            "media": true,
            "timeout": 30 } }
```

```json
{ "id":"c-7", "type":"reply", "status":"ok",
  "result": { "channel":"cb-7f3a", "call_id":"<uuid>",
              "sip_call_id":"<cid>", "state":"calling" } }
```

**The channel id is yours.** `args.channel` is required and siphon never mints
one: a controller stages its per-call context — routing, media plan, its own
state — keyed on an id it chose *before* anything reaches the network, and an API
that returned the id instead would force a round-trip that a well-built
controller has designed out. Reusing the id of a **live** channel answers
`conflict` (distinguishable from `bad_request`: the frame is fine, the id just
collides, and retrying the same one can never succeed). Once the call is gone the
id is free again.

**The reply is the local action, not the outcome.** It comes back as soon as the
INVITE is on the wire, while the callee is still ringing — which is what lets you
start ringback or a prompt during ring, and what stops one ringing phone
serialising the connection's whole command stream. What happens next arrives as
events on your id:

| event | payload | when |
|---|---|---|
| `ChannelStateChange` | `{state:"ringing"\|"progress", code, early_media, sdp?}` | a 1xx from the callee (`progress` when it carried SDP) |
| `ChannelStateChange` | `{state:"answered", code, sdp?}` | the callee answered; siphon has ACKed |
| `StasisEnd` | `{reason:"rejected", code, response}` | the callee rejected it — the SIP cause, since there is no A-leg it was relayed to |
| `StasisEnd` | `{reason:"bye"}` / `{reason:"ring timeout"}` / `{reason:<hangup reason>}` | the call ended |

**Media.** Exactly one plan is required, because an INVITE with no offer and no
way to answer the callee's leaves its 2xx unanswerable (RFC 3261 §13.2.2.4) — a
connected call with no audio:

- `sdp` — your own offer, carried verbatim. Works on any backend, or none.
- `media: true` — siphon anchors the leg on the media backend: the INVITE goes
  out offerless, the callee offers in its 2xx and siphon answers it locally with
  the answer on the ACK. The session is keyed on the leg's SIP Call-ID, so
  `play` / `dtmf` / `hold` / `stream_start` all work against it exactly as they do
  for an inbound-anchored channel. `profile` (default `rtp_passthrough`) and
  `ws_uri` shape it. Requires the `siphon-rtp` backend — anything else answers
  `unsupported_verb` at the command rather than connecting a mute call.

**Identity.** `from` / `from_display` / `to_display` / `p_asserted_identity`
(RFC 3325 §9.1) and arbitrary `headers` all land on the INVITE. `privacy:
"restricted"` anonymises From and asserts `Privacy: id` while keeping the real
identity in `P-Asserted-Identity` for the trusted next hop (RFC 3323 §4.1 /
TS 24.607) — applied last, so a custom header cannot undo it. Dialog-defining
headers in `headers` (Via, From, To, Call-ID, CSeq, Contact, Max-Forwards,
Content-Length, Route, Record-Route) are ignored: the stack owns them, and
overwriting one would leave the leg unaddressable for its own ACK / BYE.

**Ending it.** `hangup` works on an originated channel like any other: a BYE once
answered, and a CANCEL (RFC 3261 §9.1) while it is still ringing — never a SIP
response, which a UAC has no business sending to the party it is calling. The
same CANCEL fires when `timeout` (default 30 s, `0` to disable) elapses unanswered.

Refusals are typed and separately actionable: `bad_request` (missing/contradictory
args, unparseable URI, bad `privacy`), `conflict` (the id is in use), `not_found`
(no route to the target), `unsupported_verb` (the backend cannot serve the media
plan), `unavailable` (the B2BUA is not running, or the commanding connection has
gone — nothing would own the call).

In-process, the same primitive is
[`b2bua.originate(...)`](call.md#placing-a-call-b2buaoriginate), which returns the
new leg's SIP Call-ID and drives the ordinary `@b2bua.on_answer` / `on_failure` /
`on_bye` handlers.

The `bridge` verb — joining two legs this process already owns — arrives in a
later phase over the same envelope. The client SDK facade methods for the media,
transfer and originate verbs land alongside it (until then, reach the verbs
through the generic `command(verb, args)` escape hatch).

An **outbound REFER** — the `refer` verb, where the app asks siphon to transfer a
call — reports its far-end verdict as events, never in the command reply. The
reply is `{refer: "sent"}` and means exactly that: RFC 3515 §2.4.4 makes the 2xx
to a REFER "accepted for processing", with the real outcome arriving afterwards
on the implicit subscription as a `message/sipfrag` NOTIFY. Folding that into the
reply would mean blocking a command on the far end, so the rail carries it as:

- `TransferProgress` — the transfer moved but is not finished. Never a success.
- `TransferCompleted` — the referee reported a 2xx on the terminating NOTIFY.
- `TransferFailed` — it did not happen.

All three share the payload `{stage, refer_to?, code?, reason?, attempt?}`, where
`stage` says where the verdict came from and `code`/`reason` carry the SIP status
it rests on (the REFER's own response, or the sipfrag status):

| stage | event | meaning |
|---|---|---|
| `accepted` | `TransferProgress` | 2xx to the REFER — taken on for processing, no outcome yet |
| `challenged` | `TransferProgress` | 401/407, answered with the call's credentials; `attempt` is which try |
| `notify` | `TransferProgress` | a non-terminating sipfrag NOTIFY (e.g. `100`, `180`) |
| `transferred` | `TransferCompleted` | terminating sipfrag NOTIFY with a 2xx |
| `refused` | `TransferFailed` | terminating sipfrag NOTIFY with a 3xx+ — the referee tried the target and it failed |
| `rejected` | `TransferFailed` | the referee refused the REFER itself: the transfer never started |
| `unauthorized` | `TransferFailed` | challenged with no way to answer (no credentials, unparseable challenge, retry cap) |
| `no_outcome` | `TransferFailed` | the subscription ended with no usable status — never read as success |
| `call_ended` | `TransferFailed` | the call was torn down with the transfer still outstanding |

`attempt` is the 1-based REFER attempt the verdict is about, so a carrier that
challenges and is answered (`TransferProgress{stage: "challenged", attempt: 1}`)
is distinguishable from one that refuses (`TransferFailed{stage: "unauthorized"}`)
even though both carry the same 407. Exactly one terminal event
(`TransferCompleted` / `TransferFailed`) is emitted per `refer`, including when
the call dies mid-transfer — a transfer is never left pending.

`bridge` / `originate` verbs arrive in later phases over the same envelope. The
client SDK facade methods for the media verbs and the transfer verbs land
alongside them (until then, reach the verbs through the generic
`command(verb, args)` escape hatch).

The complete wire reference, both connection modes end to end, and two
low-level example clients (one Python, one TypeScript) that drive calls with no
SDK live in the repository:

- Protocol + example clients:
  [`examples/remote_control/`](https://github.com/siphon-project/siphon-sip/tree/main/examples/remote_control)
- SDK sources:
  [`siphon-control-sdk/`](https://github.com/siphon-project/siphon-sip/tree/main/siphon-control-sdk)
  (`siphon-control-proto` is the shared DTO crate — the single source of truth
  for the frames above)
