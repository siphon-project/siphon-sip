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

async def main():
    async with client:                        # closes on the way out
        await client.run()                    # connect, dispatch, reconnect + resync

asyncio.run(main())
```

Close the client when the app is done — `async with`, or `close()` explicitly.
`run()` is driven by a background task, and each handed-over call is dispatched
from another one; nothing joins them and they outlive the asyncio loop, so an app
that exits without closing leaves them delivering results into a loop, and then
an interpreter, that is no longer there. The SDK drops those late callbacks
rather than crashing on them, but closing means there is nothing to drop.

`Call` verbs: `answer()` / `answer_with(code, …)` /
`answer_anchored(profile=None, ws_uri=None)`, `ring(reason=None)`, `progress()`,
`reject(code, reason)`, `hangup(reason=None)`, `drop(reason=None)`,
`refer(to)` / `transfer(to)`, `dial(targets, …)` / `cancel_dial(reason=None)`,
`route(targets, …)`, `accept_refer(…)` / `reject_refer(code, reason=None)` /
`complete_refer(code, reason=None)`, `replace_peer(…)`,
`bridge(with_channel, …)` / `unbridge(reason=None)`,
`play(…)` / `play_file(file)` / `stop()` / `dtmf(digits, …)` / `hold()` /
`unhold()`, `stream_start(ws_uri, …)` / `stream_stop()`,
`record_start(…)` / `record_stop(recording_id=None)`,
`set_header(name, value)` / `get_header(name)` / `remove_header(name)`,
`set_var(key, value)` / `get_var(key)`, plus the generic
`command(verb, args=None)` escape hatch and
`next_event()`. A rejected command raises `ControlError` carrying a stable
`.code`.

`refer()` / `transfer()` resolve as soon as siphon has sent the REFER — RFC 3515
§2.4.4 delivers the outcome afterwards, on the implicit subscription. Read it off
the event stream with the module-level `is_transfer_final(kind)` and
`transfer_outcome(event)` rather than matching the wire strings by hand
(`isTransferFinal` / `transferOutcome` in TypeScript, `CallEvent::is_transfer_final`
/ `CallEvent::transfer_outcome` in Rust). A verb the configured media backend
cannot carry out raises with `code == "unsupported_verb"`: the stream and
record verbs on rtpengine or rtpproxy, and `play(repeat="inf")` there.

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

A **synchronous** `@b2bua.on_invite` must not `time.sleep()` to hold the call —
that pins a script-executor worker for the whole wait, on every inbound call.
Use an `async def` handler and `await asyncio.sleep(...)`, which is the supported
shape (the same handler already awaits `rtpengine.offer` / `answer_local` between
the offer and the 200), or hand the call over un-answered and let the controller
do the waiting with `ring` — see below.

### Waiting in the controller instead

A routing script can wait, but only a routing script can *decide*; an
application that took the call **un-answered** (`handover()` without
`answer=True`) can ring for as long as its own policy says with `ring`, and then
connect the caller with an anchored `answer`:

```python
@client.on_call
async def handle(call):
    await call.ring()                             # 180, for as long as we like
    agent = await pick_an_agent(call)             # only the app knows when
    await call.answer_anchored(profile="voice_ai")
```

Answering plainly and attaching a stream afterwards is not the same thing:
`received_from`, echo cancellation and the VAD engine are properties of the
answer, not of a bridge attached after it.

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
                              "result":{...} }   // or "status":"error",
                                                 // "error":{code,message,details?}
event    (siphon → client)  { "type":"event", "event":"StasisStart",
                              "channel":"<id>", "call_id":"<uuid>",
                              "sip_call_id":"<cid>", "payload":{...} }
```

Every event carries the stable id triple `{channel, call_id, sip_call_id}` —
`sip_call_id` is byte-identical to the CDR `call_id` and the HEP correlation
chunk, so logs join Homer and billing with no mapping table.

A failed reply's `error` is `{code, message, details?}`. `code` is the stable
token to branch on, `message` is prose for a human, and `details` — present only
when a refusal has something to add — is a JSON object of machine-readable
fields, so a controller never has to parse the prose:

```json
{ "id":"c-7", "type":"reply", "status":"error",
  "error":{ "code":"bad_request",
            "message":"play args.blob is 323832 bytes of audio, over the 261120-byte limit …",
            "details":{ "verb":"play", "argument":"blob",
                        "bytes":323832, "limit_bytes":261120 } } }
```

### Finding a refusal in siphon's log

Every command siphon applies logs one line. A command that was **carried out**
logs `control plane: command applied` at `debug`; a command that was **refused**
logs `control plane: command refused` — at `warn` when the controller asked for
something impossible, at `error` when the stack could not do something possible
(`unavailable`, the code for "the thing behind this verb is not there"). One
message string for both refusal levels, so a single grep finds them all and the
level is what says where to look next. Fields: `app`, `module`, `verb`,
`channel`, `sip_call_id`, and on a refusal `code` and `error`.

`sip_call_id` is the join key: a channel id appears nowhere on the wire, so it is
what lets a refused verb be lined up against a capture, a CDR and HEP.

### Phase-1 verb set

| verb | module | args | notes |
|---|---|---|---|
| `originate` | sip | `{channel, to \| aor, from?, from_display?, to_display?, next_hop?, p_asserted_identity?, privacy?, headers?, sdp \| body + content_type? \| media, profile?, ws_uri?, timeout?, on_lost?, vars?, session_timer?, strategy?, total_timeout?}` | place an outbound call under a **caller-supplied** channel id; returns as soon as the INVITE is on the wire. `aor` rings every phone registered at it, each over its own flow and Path, and the first to answer becomes the channel's call (`strategy` and `total_timeout` go with `aor` only). See [ringing a registered AoR](#ringing-a-registered-aor-originate-aor) |
| `answer` | sip | `{code, reason?, body?, content_type?, anchor?, profile?, ws_uri?}` | UAS 2xx to the parked A-leg. With `anchor` (or a `profile` / `ws_uri`, which imply it) siphon synthesizes the RFC 3264 answer against the media engine and anchors the leg's audio to it in the same act — the verb form of `call.handover(answer=True, …)`, and the only way an app that took the call **un-answered** can connect it. Without a `ws_uri` the leg is anchored on the engine with **no bridge** — which is what `play`, DTMF and recording need, and what an IVR menu, a queue announcement, music on hold and a voicemail greeting all are. `siphon-rtp` only: on rtpengine / rtpproxy it answers `unavailable` rather than a 200 with nothing behind it, and on any media failure the 2xx is never sent, so the call stays parked and answerable |
| `ring` | sip | `{reason?}` | `180 Ringing` — alerting only (RFC 3261 §13.2.1); a body is refused |
| `progress` | sip | `{code, reason?, body?, content_type?, anchor?, profile?, ws_uri?}` | a UAS 1xx, optionally opening an early-media path with SDP (RFC 3960 §3.1); defaults to `183 Session Progress`. With `anchor` (or a `profile` / `ws_uri`, which imply it) siphon synthesizes the early-media SDP against the media engine instead of taking a `body` (pass one or the other), and the later 2xx repeats that answer. An anchored progress needs a 101-199 code, since a 100 carries no body. On a media failure nothing is sent and it answers `unavailable`, with the call still parked |
| `reject` | sip | `{code, reason?}` | final non-2xx + tear down |
| `hangup` | sip | `{reason?}` | BYE an answered call, or reject an unanswered one |
| `drop` | sip | `{reason?, ban?}` | abandon an **unanswered** call with no final response and no CANCEL on the wire (the `100 Trying` siphon sent when the INVITE arrived has already gone) and release it; `ban: true` also scores the caller's source toward an auto-ban; refused (`invalid_state`) on an answered call, whose dialog is owed a BYE, and on an `originate {aor}` whose phones are still ringing, whose INVITEs are owed a CANCEL (`hangup`). See [dropping unsolicited traffic](#drop--abandon-a-call-without-answering-it) |
| `refer` | sip | `{to, replaces?}` | in-dialog REFER on the A-leg |
| `accept_refer` | sip | `{target?, next_hop?, mode?, timeout?, profile?, number_policy?, format?, from?, from_display?, p_asserted_identity?, privacy?, headers?}` | accept a pending inbound REFER (from a `TransferRequested` event) and run the transfer. `mode` is `terminate`, `transparent` or `controller`; with `controller` siphon answers `202` and dials nothing, the app carries the transfer out and reports with `complete_refer` within `timeout` seconds. `target` is a URI, `{uri}` or `{aor}` — see [inbound REFER](#an-inbound-refer-on-a-controlled-call) |
| `reject_refer` | sip | `{code?, reason?}` | reject a pending inbound REFER with a final non-2xx (default `603 Decline`) |
| `complete_refer` | sip | `{code, reason?}` | report how a transfer accepted with `accept_refer {mode: "controller"}` went: siphon sends the referrer the sipfrag NOTIFY that ends its subscription, with this status (200-699, a 2xx for success). Report before releasing the referrer's leg — see [inbound REFER](#a-transfer-the-application-carries-out) |
| `bridge` | sip | `{with, on_peer_hangup?, profile?}` | join this channel to another the app owns; the reply says the media was negotiated, `ChannelBridged` says the audio meets. `profile` names one media profile for the pair — see [`bridge`](#joining-two-legs-bridge) |
| `unbridge` | sip | `{reason?}` | break a bridge — both legs stay answered, owned and held |
| `replace_peer` | sip | `{target, next_hop?, replace_a_leg?, profile?, number_policy?, format?, timeout?, from?, from_display?, p_asserted_identity?, privacy?, headers?}` | swap one party of this answered call for a freshly dialed target, no REFER involved; the replaced leg stays up while the target rings, `PeerReplaced` says the swap landed |
| `dial` | sip | `{targets, strategy?, timeout?, headers?, profile?, from?, from_display?, p_asserted_identity?, privacy?, on_answer?, ringback?}` (identity fields also per target, as is the called party `to?`) | ring B-legs while the caller stays **unanswered** and the app keeps the channel; refused (`invalid_state`) on an answered call with `error.details: {verb: "dial", reason: "already_answered", call_state}` — see [`dial`](#dial--ring-while-the-caller-waits). With `on_answer: "bridge"`, ring phones for a caller the app already **answered** and anchored, play `ringback` while they alert, and bridge the one that picks up — see [`on_answer`](#dial-on_answer-bridge--ring-phones-for-an-answered-caller) |
| `cancel_dial` | sip | `{reason?}` | give up on the dial ringing for this channel's caller and leave the caller alone: the phones are CANCELled and the dial ends in `DialFailed` with code 487 — see [`cancel_dial`](#cancel_dial--stop-a-dial-and-keep-the-caller) |
| `route` | sip | `{targets, strategy?, headers?}` | return control to siphon: un-park the call and dial the B-leg via LCR sequential failover. Refused (`invalid_state`, `error.details: {verb: "route", reason: "dial_in_progress"}`) while a `dial` still rings for the call, since `route` releases the channel the dial reports on: `cancel_dial` first |
| `set_header` / `remove_header` / `get_header` | sip | `{name, value?}` | on the stored A-leg INVITE |
| `play` | sip | `{file\|db_id\|blob\|tone\|url, repeat?, start_ms?, duration_ms?, gain_decibels?, to_tag?}` | play an announcement on the A-leg media (fire-and-forget); the reply and a `PlayStarted` event carry the `play_id` |
| `stop` | sip | — | stop the announcement currently playing |
| `dtmf` | sip | `{digits, duration_ms?, volume_dbm0?, pause_ms?, to_tag?}` | inject DTMF digits toward the A-leg |
| `hold` / `unhold` | sip | — | silence the call's media on the engine, in both directions, and restore it; a media gate, not a SIP hold |
| `stream_start` | sip | `{ws_uri, mode?, direction?, channels?, sample_rate?, profile?}` | attach a WebSocket audio tee (`mode: tee`, the default) or takeover bridge (`mode: bridge`) (siphon-rtp backend only) |
| `stream_stop` | sip | `{mode?}` | detach the WebSocket audio tee (`mode: tee`, the default) or bridge |
| `set_var` / `get_var` | — | `{key, value?}` | per-call variables (drain with the call) |
| `resync` | — | — | re-attach + enumerate this app's owned calls |
| `describe` | — | — | list the registered adapters + their verb/event schema |

`route` is the consult-and-return flow: an app parks a call (deferred handover),
decides routing out-of-process (LCR / rating / business logic), then hands
control back to siphon with the decision. `targets` is a non-empty array of
either bare URI strings or objects
`{uri, next_hop?, headers?, timeout?, reroute_after_progress?}`. A target's
`timeout` bounds the wait for that carrier to show progress (a 101-199); a
carrier that has keeps the call to the later of its `timeout` and 30 s, then
the call fails with `408` rather than trying the next target, unless the target
sets `reroute_after_progress: true` (see
[ring timeout and progress](../cookbook/least-cost-routing.md#ring-timeout-and-progress)).
`strategy` defaults to `"sequential"` (v1 runs the LCR sequential-failover
engine only, so anything else is a typed `unsupported_verb`, never a silent
sequential); `headers` is an optional object applied to every attempt's B-leg
INVITE. On success siphon replies `{state: "routing", targets: N}`, emits a
`StasisEnd{reason: "routed"}` on the owning connection (control returned, the
call lives on), then owns the call: it dials the first carrier and advances
through the rest on reject/timeout. Once every carrier has failed,
`@b2bua.on_failure` runs and decides how the call ends, or routes it somewhere
else (see [the handler model](../handler-execution-model.md)). `continue` (bare
hand-back, siphon re-decides routing through the
script's `@b2bua.on_*` handlers) is a follow-up, pending the control-loss
`fallback` re-dispatch path.

**Ringing and early media are two verbs, not one.** RFC 3261 §13.2.1 makes the
`180 Ringing` the "callee is being alerted" signal and §21.1.2 gives it no
session semantics; RFC 3960 §3.1 puts early media on the response that carries
the SDP. So `ring` sends a plain 180 and refuses a body — an application rings
for an interval of its **own** policy's choosing, then answers — and `progress`
is the one that opens an early-media path. A provisional's reply names which it
was: `{state: "ringing"|"progress", code, early_media}`, the same vocabulary as
the callee-side `ChannelStateChange` on an originated leg, so there is one
mapping to learn rather than two.

**`StasisEnd` carries the hangup cause and, where a final response was involved,
the SIP status.** `reason` is always present and says why siphon ended the call
(`bye`, `cancelled`, `failed`, `rejected`, `media_failed`, `transfer_failed`,
`routed`, `dropped`, or a hangup / drop reason the app supplied); `code` and
`response` ride alongside it whenever a SIP final response was part of the
teardown — `487` on a CANCEL either way round, `408` on the answer timeout
(`503` when a `route` sequence ends on it with no carrier having sent a 101-199),
the callee's own status on a rejected originated leg, and the status siphon sent
on a `reject` / an unanswered `hangup` / the handoff deadline (`503`). A teardown
with no SIP response — an ordinary BYE, a script-driven terminate, a `drop` —
omits both keys rather than inventing one, so `code` present always means a real
status was on the wire.

The media verbs (`play` / `stop` / `dtmf` / `hold` / `unhold` / `stream_start` /
`stream_stop`) act on the controlled A-leg's anchored media session. They are
resolved against the configured media backend and answer with a typed reply the
same way every other verb does — never a hang:

- `play` is **fire-and-forget**: the reply confirms the backend *accepted* the
  command (`{state: "playing", play_id?, duration_ms?}`), it does not wait for
  the prompt to finish. The source is exactly one of `file` (a path on the media
  host), `db_id` (a prompt in the engine's DB), `blob` (base64-encoded audio,
  since the wire is JSON), `tone` (a synthesised call-progress tone) or `url`
  (a WAV the engine fetches). The accept is also pushed as a **`PlayStarted`**
  event, payload `{source, play_id?, duration_ms?}`, so a controller that runs
  its playback logic off the event stream — a watchdog on a source that may
  never produce audio, a gain ramp on a prompt — has one ordered place to hang
  it. `play_id` is the same value in both, and is what a targeted `stop`
  addresses; it is **omitted** on backends that assign no handle (rtpengine /
  rtpproxy) rather than faked. The reply and the event travel on different paths
  and either may land first — correlate on `play_id`, not on arrival order. The media contract answers `play`
  *accept-on-start*, so `PlayStarted` means the engine armed the playback, not
  that audio has reached the wire: a `url` source accepts before its body has
  arrived, which is why `duration_ms` can be absent. A play the backend refuses
  answers with a typed error and pushes **no** `PlayStarted`, so "no start event
  yet" always reads as "not started".
- `play`'s `repeat` is a **total play count**, or the string `"inf"` to play
  until a `stop` — music on hold. An endless play's accept carries
  no `duration_ms`. `"inf"` needs the `siphon-rtp` backend: rtpengine and
  rtpproxy carry only a count and answer `unsupported_verb` rather than playing
  once. An argument that is present and unusable — a `repeat` that is neither,
  a `start_ms`, `duration_ms` or `gain_decibels` that is not a number, a
  `to_tag` that is not a string — is refused `bad_request` with
  `error.details: {verb: "play", argument, reason: "invalid_value"}`. It is not
  dropped: a `repeat` read as absent plays the prompt once and answers `ok`.
- `hold` silences the call's media on the engine and `unhold` restores it. It
  is a media gate, not a SIP hold: the audio is replaced with silence in **both**
  directions and nothing is sent on either dialog, so no phone shows a held
  call. It applies to a call the engine transcodes, records or streams; on one
  it only relays it is refused `invalid_state` with `error.details: {verb,
  reason: "media_not_processed"}`. To hold **one party** of a bridge, with the
  `sendonly` re-offer a phone displays (RFC 3264 §8.4), use `unbridge`.
  Dropping packets outright (`block`/`unblock`) is a separate future gate verb.
- `stream_start` / `stream_stop` attach and detach a **WebSocket audio tee** —
  an *additive* copy of the live call's audio for transcription / agent-assist /
  compliance, not a takeover of the media path. This is a `siphon-rtp`-backend
  feature: on rtpengine / rtpproxy it answers `unsupported_verb` rather than a
  hollow success. `direction` is `both` (default) / `caller` / `callee`,
  `channels` is `1` (mixed mono) or `2` (caller/callee stereo), and
  `sample_rate` is the L16 rate in Hz (a multiple of 1000 within 8000–48000).
  `mode: bridge` is the opposite operation, a takeover that makes the
  WebSocket server the leg's far side; it takes none of the tee's shaping
  arguments and refuses them with `bad_request`. A bridge takes `profile`
  instead (refused on a tee): the name of a media profile whose bridge
  settings (`ws_sample_rate`, `noise_suppression`, `echo_cancellation`,
  `ws_vad`, `ws_barge_in`) the bridge runs with, read as `answer` with
  `ws_uri` reads them. Without it the engine runs the bridge at the leg's own
  rate with uplink processing off, and a re-point keeps what the bridge had;
  neither shows in the `ok` reply. An unknown name is `bad_request` with
  `reason: unknown_profile`, and nothing reaches the call. An absent `mode` means `tee`,
  but the SDKs always send it, so a controller that asked for a tee never gets
  a takeover from a server whose default differs.
- **WebSocket URI placeholders.** A `ws_uri` may name `{call_id}`,
  `{from_tag}`, `{from_user}` and `{to_user}`, and siphon expands them before
  the engine sees the URI, the same way on every path: `stream_start` (either
  `mode`), `answer` / `progress` / `originate` with `ws_uri`, a media profile's
  `ws_uri` or `ws_tee` applied by those verbs, and a script's `ws_uri=`,
  `rtpengine.attach_ws_tee` and `attach_ws_bridge`.
  `{call_id}` is the **SIP Call-ID** of the channel's call — the frame's
  `sip_call_id`, not its `call_id` (siphon's own id for the call). For an
  `originate` it is the placed leg's own Call-ID. `{from_tag}` is the tag the
  engine keyed the leg on: the caller's From-tag on an inbound call, the
  callee's To-tag on an `originate`. `{from_user}` / `{to_user}` are the user
  parts of the call's From and To. A placeholder siphon does not know, or one
  the call has no value for, is refused (`stream_start` answers `bad_request`)
  rather than sent to the engine as written.
- A call with no anchored media session answers `not_found`; a backend that
  cannot perform the op answers `unsupported_verb`; any other backend failure
  answers `unavailable`.
- An inline `blob` is capped at **261,120 bytes of audio** — the worst-case
  encoding bound of the media control frame, so it is content-independent and a
  controller can apply the same check itself. Over it, `play` answers
  `bad_request` naming the argument and the bound, with
  `error.details: {verb, argument, bytes, limit_bytes}`, before the media session
  is resolved and before any frame is built. A longer prompt belongs in
  `args.file` or `args.url`, which ship a reference rather than the bytes.
  (Previously an oversized blob reached the frame encoder and came back as
  `unavailable` — the code for an unreachable engine — so a controller retried a
  prompt that could never be played.)

### `drop` — abandon a call without answering it

```json
{ "verb": "drop", "target": {"channel": "ch1"},
  "args": { "reason": "no flow claims this number", "ban": true } }
```

A PBX's SIP port is reachable from the internet by definition — carriers deliver
to it — so it is swept continuously. `reject` and an unanswered `hangup` both put
a final response on the wire, and to a scanner probing for extensions that
response *is* the result: a `404` separates "no such user here" from "filtered",
and confirms the number it guessed. Neither existing control covers it —
`security.failed_auth_ban` scores authentication failures and an INVITE to an
unknown number attempts none, the transport allow list is whitelist-only and so
unusable where subscribers roam, and `security.apiban` covers *known* bad
addresses, which by construction is not the first probe from a new one.

The controller holds the only knowledge of which numbers are real, so it is the
only thing that can decide an INVITE is unsolicited. `drop` is what it acts on
that decision with: **no final response** goes to the caller, and the call is
released. "Nothing on the wire" means exactly that, and not less: siphon answers
every INVITE it accepts with `100 Trying` as soon as it arrives (RFC 3261
§8.2.6.1), before the call is created and so before a controller has heard of
it, and that `100` has already gone by the time `drop` can be sent. It stands —
the open port disclosed that a server exists, which is all a `100` says. What
`drop` withholds is the `404`/`486`/`603` that would say whether the number is
real.

Not replying at all is **not** the same thing, which is why this is a verb and
not a convention: the call would stay parked until the application's own
deadline, with the caller's INVITE retransmitting against state siphon is still
holding (RFC 3261 §17.2.1). The drop releases everything the unanswered teardown
releases — every B-leg a `dial` left ringing is CANCELled (RFC 3261 §9.1),
siphon's reliable provisionals to the caller stop being retransmitted
(RFC 3262 §3), an anchored media session is deleted, the call actor and its event
receiver are removed — so a sweep costs one dropped call apiece and leaves
nothing behind.

Replies `{channel, state: "terminated", response_sent: false}`, and pushes a
`StasisEnd` carrying `reason` (the argument, or `dropped`) with **no** `code` or
`response`, since no SIP final response was part of the teardown.

- **An answered call is refused**, `invalid_state`: RFC 3261 §15 owes that dialog
  a BYE, and the call is left exactly as it was so `hangup` can still send one.
- `reason` is for the record, not the wire. It reaches siphon's log (one `info`
  line naming the call, its `Call-ID`, the source address and the reason) and the
  CDR, which records `disconnect_initiator: "control"`, the reason as
  `sip_reason`, and `response_code: 0` — a dropped call must read as deliberate,
  never as a leak.
- A call that ended while the controller was deciding answers `not_found`.

**`ban: true` makes the verdict stick.** Silence alone costs a scanner nothing:
it gets no answer and moves on to the next number at the same rate, which on a
public port can be several INVITEs a second, indefinitely, below any sensible
`rate_limit`. With `ban`, siphon also scores the caller's source address in the
`security.failed_auth_ban` store, so a source the controller keeps dropping is
banned and refused at the transport before its next INVITE is parsed.

- The weight follows how far the source address can be believed. Over TCP, TLS,
  WS or WSS the handshake proved it, and one drop counts as a strong signal
  (`strong_signal_weight`). Over UDP a single datagram can name any address, so
  one drop counts once, the same as a rejected credential over UDP: forging a
  ban onto somebody else's address takes a full `threshold` of spoofed INVITEs,
  never one.
- `trusted_cidrs` are never scored, so a trunk whose call the controller
  misroutes cannot be banned through this verb.
- A no-op without `security.failed_auth_ban`, which is what holds the ban store.
- Only a successful drop scores: a refused one (`invalid_state`, `not_found`)
  leaves the source alone.
- `ban` must be a boolean; anything else is `bad_request`, since a `"true"`
  string read as false would drop the call and ban nothing.
- A ban is logged once, at `warn`, when the source crosses the threshold, and
  shows up in `GET /admin/bans` like any other.

### Recording

```json
{ "verb": "record_start", "target": {"channel": "ch1"},
  "args": { "direction": "ingress", "max_duration_ms": 60000, "silence_ms": 4000 } }
```

Records the call's **decoded** audio to a wav file and replies with a
`recording_id`. `record_stop {recording_id?}` finishes one, or every recording
on the call when the id is absent.

`max_duration_ms` and `silence_ms` are the two stop conditions a voicemail
greeting announces — "you have sixty seconds" and "stop talking and we'll hang
up" — and the engine evaluates both, where the decoded audio already is.
`direction` is `ingress` (the default: what the parties *sent*, which is what a
message is), `egress` or `both`; `channels` is `mono` or `stereo`.

`RecordingFinished {recording_id, path, reason, duration_ms}` arrives when the
file is **closed**, which is the event worth waiting for: attaching the audio to
an email on the `record_stop` reply would race a half-written file. `reason` is
`stopped`, `max_duration`, `silence`, `call_ended`, `bridged` or `error` — a
voicemail box reads those differently.

`bridged` is a recording that ended because the leg was **bridged**, on a call
that is still up. A leg siphon answered itself is anchored on a single-party
engine session; forming a bridge moves its media onto the pair's own session
and retires the old one, with the recording on it. The same happens to a
recording on the leg being bridged in. To record the conversation, issue
`record_start` again once `ChannelBridged` arrives.

It works on a single-leg, engine-terminated call, which is what a voicemail box
is. This is **not** `li.record()`: that is SIPREC, where a recording *server*
gets its own leg. `siphon-rtp` only — rtpengine's `start recording` writes a
pcap of the wire with no id to stop or correlate by, and rtpproxy has no
recording at all, so both answer `unsupported_verb` rather than produce an
artefact nobody asked for.

Inbound in-band DTMF on a controlled call is pushed to the owning connection as
a `ChannelDtmfReceived` event, payload `{digit, duration_ms, volume, from_tag}`
(`from_tag` identifies which party pressed), so an IVR / AI app **collects digits
off the event stream** rather than through a blocking verb — there is
deliberately no server-side `collect_dtmf` (it would park an I/O worker). This is
additive to the in-process `@rtpengine.on_dtmf` dispatch: the digit fires both,
and it needs no extra configuration beyond the DTMF-log wiring the media engine
already uses.

On a **bridged pair** both legs relay through one engine session, and the
engine reports a digit on that session with the `from_tag` of the party that
pressed it. siphon sends `ChannelDtmfReceived` to that party's channel only,
never to both. The same holds for the other per-party media events on a pair:
`PlayFinished`, `RecordingFinished`, `WsTeeStarted` / `WsTeeEnded` and
`WsBridgeStarted` / `WsBridgeEnded` go to the channel of the party whose tag
they carry (the anchor's for a prompt, recording or stream started on the
anchor's channel). An event whose tag names neither party is not delivered.

A digit signalled as **SIP INFO** rather than in the media (RFC 2976 / RFC 6086
`application/dtmf-relay`, which some handsets and trunks send instead of
RFC 4733) produces the same event, from the same code path — an app collecting
digits does not have to know which wire carried them. The INFO itself is relayed
to the far leg on a two-leg call and answered `200` on a one-legged one; an INFO
body that is not DTMF is relayed or answered but produces no event.

### Media summary

When the media engine ends a media session it reports what the session
carried, and siphon publishes that on each channel whose media the session
carried as `MediaSummary {reason, duration_ms, legs}` (siphon-rtp only).
`reason` is `delete` or `media_timeout`; `duration_ms` has about one-second
grain. `legs` has one entry per party, matched on `tag` (the offerer's
From-tag, the answerer's To-tag): `packets_in`, `bytes_in`, `packets_out`,
`bytes_out` and `packets_dropped` (the engine's own drops, not network loss)
always, and, where the engine measured them, `codec`, `payload_type`, `ssrc`,
`egress_ssrc`, `packets_lost`, `loss_percent`, `jitter_ms`, `rtt_ms`,
`mos_average` / `mos_min` / `mos_max` with `mos_basis` (`full` or
`loss+jitter`), `text` (RFC 4103 counters), `local_address`,
`remote_address` and `media_started_at_unix_ms` (when that party's first
packet reached the engine). A figure the engine did not measure (a leg on the in-kernel
relay, or one that never received media) is **absent**, not zero.

When you see it:

- A session the engine reaped on **media timeout**, or a single-party session a
  **`bridge`** replaced with the pair's, ends while the call goes on; its
  summary arrives on the live channel.
- The end-of-call summary of an **ordinary hang-up** (a BYE, `hangup`, a
  failure) arrives **after `StasisEnd`**. Teardown emits `StasisEnd` and
  removes the channel at once, while the media delete runs on its own task, and
  the engine produces the summary only after that delete. siphon keeps the
  owning connection reachable for it for 30 seconds: the summary goes to that
  connection, with the `channel` id the call had, even though the channel no
  longer exists. After 30 seconds, or once that connection has disconnected,
  a late summary is dropped (it is still in the media CDR, `method: MEDIA`,
  when CDRs are enabled). No other connection or app ever receives it.
- A **bridged pair** (`bridge`, or `dial {on_answer: "bridge"}`) relays
  through one engine session of its own, which carries both legs, so its
  summary goes to **both** channels, once each, and its `legs` cover both
  parties. Each channel gets it under its own `channel` id, from its own
  owner's 30-second window: a leg that ended more than 30 seconds before the
  pair's session did (a peer that hung up while the anchor was held) misses it.
  An `unbridge` does not change this: the parted legs stay on the pair's
  session, held, until they hang up. A bridged channel therefore hears one
  `MediaSummary` per engine session it was on: its own, replaced when the
  bridge formed, and the pair's.

**Events after `StasisEnd`.** `MediaSummary` is the only event that can follow
a channel's `StasisEnd`, at most once, and only after a teardown (never after
`StasisEnd {reason: "routed"}`, which hands a live call back to siphon). A
controller must accept it for a channel it already considers ended, not treat
it as an error or an unknown channel, and must not send commands in reply: the
channel is gone and any verb on it answers `not_found`. Nothing else crosses
`StasisEnd`; a `WsTeeEnded`, `WsBridgeEnded`, `PlayFinished` or
`RecordingFinished` the teardown itself causes finds no channel and is not
delivered.

A call no controller owns publishes nothing.

### Media started

When the first packet on one of a call's media legs clears the engine's source
gate, siphon publishes `MediaStarted` on the channel of the party that leg
faces (siphon-rtp only). The engine reports it within about 20 ms of the
packet, once per leg: a two-party call raises two, and a re-latch or a
re-INVITE raises none.

```json
{"leg": "far", "from_tag": "9fd3a1", "to_tag": "77c0be",
 "source": "203.0.113.7:40000", "signalled": "192.0.2.10:4000",
 "nat_rewritten": true}
```

`leg` is `near` (the leg facing the engine session's offerer, `from_tag`) or
`far` (the answerer's, `to_tag`). It names the engine leg, not a party: before
an answer the far leg carries the callee's early media. `source` is where the
first packet came from and `signalled` where the SDP said it would;
`nat_rewritten` says whether they differ, which is a NAT between the party and
the engine. An address the engine did not report is absent, and so is
`nat_rewritten` unless both are there.

On a **bridged pair** both legs relay through one engine session: the near
leg's report goes to the anchor's channel and the far leg's to the peer's,
never to both. Each party's start time is also in `MediaSummary` and the media
CDR as `media_started_at_unix_ms`, absent for a leg that never carried media.

### Application-level events

Most events belong to a channel and reach its owner. `RegistrationChanged` does
not: a registration concerns the deployment, and the app that wants it on a
dashboard may own no channel at all.

```yaml
control:
  apps:
    - name: dashboard
      token: "${DASHBOARD_TOKEN}"
      events: [registration]
```

The frame carries no `channel`, `call_id` or `sip_call_id` — there is no call
for it to be about — and its payload is
`{aor, event, contacts: [{uri, expires, q}]}`, where `event` is `registered`,
`refreshed`, `deregistered` or `expired`. It reaches **every** connection of a
subscribed app rather than one picked round robin: a dashboard behind two
replicas needs both to see it, and there is no call here whose ownership would
decide which.

Opt-in, and empty by default — a registration storm must not land on the event
queue of an application that only places outbound calls. An `events` entry
naming a class siphon does not publish is refused at config load, because the
list is read at start-up and an app subscribed to a name nothing sends would
wait forever with nothing to tell it.

It fires whether or not a `@registrar.on_change` handler is registered: a
dashboard should not depend on a script existing.

#### Dialog state of registered AoRs: `DialogStateChanged`

`events: [dialog]` subscribes an app to the RFC 4235 state of every dialog a
registered AoR has through siphon, B2BUA calls and proxied INVITEs alike, so a
controller can serve the
`dialog` event package (busy-lamp field) truthfully: ringing, talking or idle,
per phone, ring groups and calls the phone places itself included. Every state
comes from what siphon observed on the wire; nothing is inferred.

```yaml
control:
  apps:
    - name: presence
      token: "${PRESENCE_TOKEN}"
      events: [registration, dialog]
```

The payload, all from the AoR's point of view as dialog-info renders it:

| field | meaning |
|---|---|
| `aor` | the registered AoR (its canonical registrar key, implicit-set aliases resolved to the primary) |
| `state` | `trying`, `proceeding`, `early` (ringing), `confirmed` (in a call) or `terminated` |
| `direction` | `initiator` (the phone placed the call) or `recipient` (it is being called) |
| `leg_id` | siphon's id for the phone's leg: stable for the dialog's life and unique, so usable as the dialog-info `id`. For a branch of a `dial` it is the `leg_id` the branch's `DialBranch` named |
| `call_id` | the SIP Call-ID of the phone's own dialog |
| `local_tag` | the phone's tag, `null` until known (on a call ringing the phone, until its first tagged response) |
| `remote_tag` | the other end's tag, `null` until known (on a call the phone placed, until siphon's first tagged response to it) |
| `remote_identity` | `{uri, display_name}`: the party the phone is talking to, as presented on the phone's leg — the To of the INVITE it sent, or the From of the INVITE it received |

A dialog moves only forward through the states and reports `terminated` exactly
once, on every path that ends it: a BYE from either side, a CANCEL, a final
failure, a ring timeout, a branch siphon CANCELled because another answered (a
ring group's other members), a 2xx that lost an answer glare (reported
`terminated`, never `confirmed`), a transfer's referrer, a dialog `Replaces`
took over, and every call teardown. A phone is idle when every dialog it had has
reported `terminated`. A ring group shows each member `early`, then the one that
answered `confirmed` and the rest `terminated`; `DialAnswered` names that
member's `aor` too.

**Which AoR a leg belongs to.** A leg is reported only when siphon can tell
whose it is from what it observed, never from a header a caller writes alone:

- *A call a phone places*: the From must name a registered AoR, and a live
  binding of it must vouch for the INVITE. It does when the INVITE
  authenticated (a digest challenge in `@b2bua.on_invite`) as the identity that
  REGISTERed the binding, or — for a binding stored without an authenticated
  identity, or an INVITE that presented none — when the INVITE came from the
  address that REGISTER came from. A From naming a phone, sent from anywhere
  else, is not reported. The dialog is reported once the call is going
  somewhere (routed, handed over, answered); an INVITE refused at admission, a
  digest challenge included, never shows as a call.
- *A call siphon places to a phone* (a B-leg, or an `originate`): the AoR an
  `{aor}` target of a `dial` resolved from; otherwise the one AoR with a live
  binding whose Contact is the INVITE's Request-URI. A Contact that bindings of
  two AoRs share names neither.

**INVITEs the proxy relays.** Matched to AoRs by the same rules (the caller by
a binding vouching for it, with the identity the script authenticated; each
branch by the binding its Request-URI, or its captured flow, names), and
tracked per branch: a fork shows every registered callee `early` on its own
branch (with that branch's To-tag), the one that answers `confirmed`, and the
others `terminated` when siphon CANCELs them. The state is kept by dialog
(Call-ID and tags), not by the transaction entries that retire on Timer I.

**Wire change: siphon Record-Routes a tracked INVITE.** When an app subscribes
to `dialog` and a relayed or forked INVITE involves a registered AoR on either
side, siphon adds its Record-Route to it even if the script did not call
`record_route()` (idempotent when it did). RFC 3261 §16.6 step 4 lets a proxy
stay on the path this way and §12.2 obliges both UAs to send their in-dialog
requests along the route set, which is what brings the BYE, from either end,
back through siphon. A BYE ends the dialog for both ends when it arrives, before
the script runs, so a BYE the script answers itself ends it too. An INVITE with
no registered party on either side is relayed exactly as the script left it.

A Record-Route siphon adds on its own carries a `dlgw` URI parameter, and an
in-dialog request whose topmost Route is that entry is routed by siphon along
the route set (RFC 3261 §16.12) without running the script. A script written
without Record-Route never saw a dialog's in-dialog requests and still does
not have to handle them; one that Record-Routes itself keeps handling them
exactly as before, and siphon adds nothing to its INVITEs. Responses to those
in-dialog requests still pass `@proxy.on_reply` like any relayed response.

**No endpoint can leave a phone shown in a call.** A proxy is not a party to
the dialog, so a BYE siphon never sees would leave the state standing. For a
proxied dialog siphon also ends the reported state, per phone, when:

- the binding that tied the phone to the dialog is removed — de-registered,
  expired, or reaped by registrar liveness — since the phone is no longer
  reachable through siphon (checked on the registration event and on every
  liveness pass);
- a session interval negotiated in the 2xx (RFC 4028) runs out without a
  refresh (a 2xx to a re-INVITE or UPDATE refreshes it), after a grace;
- an in-dialog OPTIONS probe (RFC 3261 §11) to that phone is answered `481`, or
  goes unanswered (or `408`) `probe_failures` times in a row. The probe is sent
  along the dialog's route set as a request from the other end, with the other
  end's tags and the CSeq the phone last received from it (`0` when it received
  none): reusing that number rather than going one higher keeps the probe from
  advancing the phone's view of the other end's CSeq space, which the other
  end's next real request would then fall below (§12.2.2 answers that with
  `500`). Only an end whose state is still reported is probed;
- it stays unanswered longer than `max_early_secs` (the §16.6 Timer C bound on
  how long a proxy lets an INVITE ring), or exists longer than
  `max_lifetime_secs`.

None of these tears the call down: siphon ends only the reported state. A
proxy is not a party to the dialog and has no business sending a BYE for one,
an unanswered probe can be a signalling path that failed while the media still
flows, and a BYE siphon generated would end a call a phone may still be in. The
other end keeps its own state until its own evidence says otherwise.

For a **B2BUA** leg the same binding check applies: a phone whose binding goes
away mid-call is reported ended, and the call is left to its own teardown,
session timer or duration cap. The B2BUA needs none of the other checks — it is
a party to both dialogs, and every way the call can end already ends them.

```yaml
control:
  dialog_state:
    probe_interval_secs: 300      # in-dialog OPTIONS to each watched end; 0 disables
    probe_timeout_secs: 8
    probe_failures: 2             # unanswered probes in a row; a 481 ends it at once
    max_early_secs: 300           # Timer C bound on ringing
    max_lifetime_secs: 43200      # hard backstop
    session_timer_grace_secs: 32
```

**Cost.** Nothing unless an app subscribes: every hook stops at the
subscription check or the tracking store's emptiness, measured at under a
nanosecond (`benches/dialog_state.rs`, `gate_unsubscribed`). With a
subscriber, each INVITE branch pays a scan of the registrar's bindings to match
its target (about 36 µs at 1,000 bindings, `match_callee_1k_bindings`; an
`{aor}` target of a `dial` skips it), and each tracked proxied call about
1.5 µs of bookkeeping from INVITE to BYE (`track_proxied_call`). A B2BUA leg's
record lives on its call and is released with it; the proxy store drains as
each dialog ends.

### An inbound REFER on a controlled call

An **inbound REFER on a controlled call** (a party asking to be transferred) is
handed to the owning app rather than the in-process `@b2bua.on_refer` path: siphon
holds the REFER un-answered and pushes a `TransferRequested` event, payload
`{refer_to, replaces?, from_tag, referrer_leg, referrer_sip_call_id}`.

Either party of the call can refer, and the event says which. `referrer_leg` is
`"a"` for the party the channel's call came from and `"b"` for the party it was
connected to — a phone transferring a call it **answered**. A B-leg has a dialog
of its own, on a Call-ID siphon generated, so `referrer_sip_call_id` is the
`leg_sip_call_id` its `DialBranch` named rather than the channel's.

`replaces` is present for an attended transfer: `{call_id, from_tag, to_tag,
early_only, local}`. `local` is set when this node hosts the dialog named:
`{call_actor_id, channel, leg, bridged_with}` — the call it belongs to, the
channel controlling that call, which leg of it the dialog is, and the channel
that call is bridged with. A `Replaces` carries a Call-ID and two tags, none of
which an application ever sees; `local` is the same dialog in the terms it
works in. It is `null` for a dialog hosted elsewhere.

One decision is pending per call. A retransmission of the held REFER is
absorbed; a second REFER on the same call while the first is undecided is
answered `491 Request Pending`.

The app decides with:

- `accept_refer` — run the transfer through siphon's shipped machinery.
  `target` overrides the Refer-To, `next_hop` steers egress
  without reshaping the R-URI, and `mode` is `terminate` (siphon-terminated: 202 +
  sipfrag NOTIFYs + re-dial the target as a new leg — the default, from
  `b2bua.default_refer_mode`) or `transparent` (forward the REFER on the far leg's
  own dialog). On a single-leg call (a voice-AI / IVR call siphon answered itself,
  no B leg) terminate mode re-dials the target off the A dialog.

  `target` is a URI string, `{uri}` or `{aor}`. An AoR is dialled the way
  `dial {aor}` dials one: over the flow its phone registered on and through the
  Path of its binding, which is the only way to reach a phone on TCP, TLS or
  WSS behind NAT. Nobody registered answers `not_found`. `next_hop` beside an
  `{aor}` is `bad_request`.

  An AoR with several registered contacts rings **every one of them**, each on
  an INVITE and a Call-ID of its own, as a forking proxy rings a party with
  several phones (RFC 3261 §16.7). The first to answer is the party brought
  into the call. Every other one is sent a CANCEL; the `487` that draws is
  ACKed, and a contact that answers in the instant before its CANCEL arrives is
  ACKed and released with a BYE, so no phone is left ringing or holding a
  dialog nobody is on. One contact refusing while another still rings reports
  nothing: the transfer fails only once none of them is left, and then on the
  best of their responses (§16.7 step 6), not whichever came last. On a
  media-anchored call each contact is offered the surviving party's media on an
  engine call of its own, and the ones that do not answer are released.
  To ring one phone of the party, name it with `{uri}`.

  `from`, `from_display`, `p_asserted_identity`, `privacy` and `headers` are
  the arguments [`dial` takes](#presenting-an-identity) and shape the leg the
  transfer dials the same way. Without them it presents what the call's own
  INVITE carried, which after a transfer is the wrong party as often as not.
  They and `{aor}` apply to `terminate`; `transparent` relays the REFER, dials
  no leg, and refuses them `bad_request` rather than accepting and ignoring
  them.

  `mode: "controller"` is the third mode, and the one where siphon does no
  transferring at all. See
  [below](#a-transfer-the-application-carries-out).
- `reject_refer` `{code?, reason?}` — decline with a final non-2xx (default
  `603 Decline`).

If the app never decides, a decision deadline answers `603 Decline` (the same
default as when no `@b2bua.on_refer` handler is registered), so a REFER is never
left pending — the referrer is always answered (RFC 3515 §2.4.2). A bad `mode`
answers `bad_request`; a decision for a call with no pending REFER (already
decided, timed out, or gone) answers `not_found`. A REFER on an **uncontrolled**
call is unaffected — it still runs the Python `@b2bua.on_refer` path.

#### A transfer the application carries out

`terminate` has siphon dial the target and `transparent` has it relay the
REFER. Neither fits a transfer the application has to perform with its own
verbs: joining two calls it bridged, or sending the call out through a flow
of its own. For those, accept with `mode: "controller"`:

```json
{"verb": "accept_refer", "target": {"channel": "c1"},
 "args": {"mode": "controller", "timeout": 30}}
```

siphon answers the REFER `202 Accepted`, sends the referrer the first NOTIFY
of its subscription (a `message/sipfrag` body of `SIP/2.0 100 Trying`,
`Subscription-State: active;expires=<timeout>`, RFC 3515 §2.4.4), and stops.
It dials nothing, moves no leg and changes no call state. The reply is
`{transfer: "accepted", mode: "controller", timeout}`, with the timeout
siphon will apply.

The application then moves the parties with `bridge`, `unbridge`,
`replace_peer` or `dial`, and says how it went:

```json
{"verb": "complete_refer", "target": {"channel": "c1"},
 "args": {"code": 200}}
```

`code` is required, 200 to 699. siphon sends the NOTIFY that ends the
subscription: a sipfrag of that status with `Subscription-State:
terminated`. A 2xx tells the referrer the transfer succeeded, anything else
that it failed. `reason` is the reason phrase in the sipfrag, used as given;
without one siphon uses its own phrase for the status (`486` is `Busy Here`,
a status it has no phrase for is `Error`). The reply is `{transfer:
"completed", code}`. `complete_refer` touches nothing but the subscription.

Rules:

- **Report before you release the referrer.** The NOTIFY travels on the
  referrer's dialog. Once the application has hung that leg up, or replaced
  it, the dialog is gone and there is nothing to send the report in:
  `complete_refer` answers `not_found`. So `complete_refer` first, then
  `hangup`.
- `timeout` is how many seconds the application has to report, default 60,
  capped at 180. A value that is not a positive whole number is
  `bad_request`. Past the deadline siphon reports for it: a sipfrag `503
  Service Unavailable` with `Subscription-State: terminated`, so the
  referrer is told the transfer did not happen instead of waiting on it. A
  `complete_refer` after that is refused.
- With no transfer awaiting a report on the call, `complete_refer` answers
  `invalid_state` with `error.details: {verb: "complete_refer", reason:
  "no_transfer_pending"}`. That covers one already reported, one past its
  deadline, and one whose referrer hung up. A call that is gone answers
  `not_found`.
- If the referrer hangs up first, its BYE is answered and the subscription
  ends with its dialog. No NOTIFY is sent.
- Until the report, a further REFER on the same call is answered `491
  Request Pending` and is not shown to the application. A retransmission of
  the accepted REFER is answered `202` again.
- `mode: "controller"` takes `timeout` and nothing else. `target`,
  `next_hop`, `profile`, `number_policy`, `format`, `from`, `from_display`,
  `p_asserted_identity`, `privacy` and `headers` all describe a leg siphon
  would dial, and it dials none, so any of them is `bad_request`
  (`error.details: {verb, argument, reason: "not_dialled"}`). The other
  modes refuse `timeout` for the same reason.
- `replace_peer` is not held off by a transfer in this mode. It is refused
  only while another replacement is in flight.
- The mode exists on the control plane only. A script has no
  `complete_refer`, so `call.accept_refer(mode=…)` and
  `b2bua.default_refer_mode` do not take it.

A worked attended transfer between two bridged calls is in the
[call transfer cookbook](../cookbook/call-transfer.md#attended-transfer-between-calls-a-controller-bridged).

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
            "timeout": 30,
            "session_timer": { "expires": 1800, "refresher": "uac" } } }
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
| `StasisEnd` | `{reason:"cancelled", code:487, response}` | the leg was abandoned before answer (RFC 3261 §9.1) |
| `StasisEnd` | `{reason:"bye"}` / `{reason:"ring timeout"}` / `{reason:<hangup reason>}` | the call ended |

**Media.** Exactly one plan is required, because an INVITE with no offer and no
way to answer the callee's leaves its 2xx unanswerable (RFC 3261 §13.2.2.4) — a
connected call with no audio:

- `sdp` — your own offer, carried verbatim as `application/sdp`. Works on any
  backend, or none.
- `body` + `content_type` — the same slot with the type spelled out, for an
  INVITE whose offer travels as one part of a `multipart/*` body (RFC 5621 §3)
  beside a part SIP does not interpret: ISUP on a SIP-I trunk (RFC 3204), a
  PIDF-LO location object (RFC 6442), an operator-specific document. You
  assemble the multipart; siphon carries it verbatim and derives Content-Length
  from it. `content_type` defaults to `application/sdp`, which makes `body`
  alone identical to `sdp`.

    The body must still carry an SDP offer — `application/sdp`, or a
    `multipart/*` with an `application/sdp` part in it. One that does not is
    `bad_request` at the command, because a callee reading the INVITE as
    offerless offers in its own 2xx and this plan has nothing to answer that
    with (RFC 3261 §13.2.2.4). The same check runs on the Content-Type after
    `headers` is applied, so rewriting the header cannot strip the offer off the
    INVITE either. Note that `args.body` is JSON text: a part whose bytes are
    not UTF-8 (raw ISUP, say) cannot be spelled on this rail today, the same
    limit `answer` and `progress` have.

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

**Session timer.** `session_timer: {expires, min_se, refresher}` runs an RFC 4028
session timer on the call over the `session_timer:` block, each key left out
defaulting as in `call.session_timer()` (1800, 90, `b2bua`). The INVITE asks for
it, the callee's 2xx says who refreshes, and siphon refreshes the dialog or
releases the call just before a session the callee let run out expires, exactly
as for [`b2bua.originate(session_timer=...)`](call.md#placing-a-call-b2buaoriginate).
Left out, the configured timer runs, if there is one. A key no timer has, a
`refresher` other than `uac`, `uas` or `b2bua`, or an `expires` / `min_se` that is
not a whole number of seconds is `bad_request`, and nothing is placed.

Refusals are typed and separately actionable: `bad_request` (missing/contradictory
args, unparseable URI, bad `privacy` or `session_timer`), `conflict` (the id is in use), `not_found`
(no route to the target), `unsupported_verb` (the backend cannot serve the media
plan), `unavailable` (the B2BUA is not running, or the commanding connection has
gone — nothing would own the call).

### Ringing a registered AoR: `originate {aor}`

`to` is one URI, resolved as written. A phone registered over TCP, TLS or WSS
behind NAT is reachable only on the connection it registered over, and one
registered through an edge proxy only through the Path its binding carries, so
resolving its Contact reaches nothing. `aor` in place of `to` rings every phone
registered at the AoR, each over its own flow and Path (RFC 5626 §5.3,
RFC 3327 §5.3; a Path outranks the flow), exactly as a `dial` to `{aor}` does:

```json
{ "id":"c-8", "type":"command", "module":"sip", "verb":"originate",
  "args": { "channel": "wake-201", "aor": "sip:201@example.com",
            "from": "sip:reception@example.com", "media": true,
            "strategy": "parallel", "timeout": 25 } }
```

```json
{ "id":"c-8", "type":"reply", "status":"ok",
  "result": { "channel":"wake-201", "group_id":"originate-group-<id>",
              "aor":"sip:201@example.com", "strategy":"parallel",
              "total_timeout":25, "state":"calling",
              "branches":[ {"leg_id":"<id>", "leg_sip_call_id":"<cid>",
                            "target":"sip:201@203.0.113.7:5060", "aor":"sip:201@example.com"} ] } }
```

`to` and `aor` are mutually exclusive, and one is required: both, or neither, is
`bad_request`. An AoR with nobody registered is `not_found` with
`error.details: {verb:"originate", reason:"no_contacts", aor}`, and nothing goes
on the wire. `strategy` and `total_timeout` apply to `aor` only and are
`bad_request` beside `to`.

Each phone is rung as its own originated call: its own INVITE (Request-URI the
registered Contact, To the AoR) with every other argument applied as for `to`.
A single registered phone is simply a group of one.

- `strategy: "parallel"` (default) rings every phone at once; `"sequential"`
  rings them one at a time, in registration q-value order, moving on when one
  declines or rings out its own `timeout`.
- The first phone to answer wins. Every other phone still ringing is CANCELled
  (RFC 3261 §9.1); one that answers anyway is ACKed with every stream rejected
  and BYEd (§13.2.2.4, §15).
- `total_timeout` bounds the whole group; when it passes, every phone still
  ringing is CANCELled. It defaults to `timeout` for a parallel group and to
  `timeout` times the number of phones for a sequential one (`0` for none).

The events arrive on your channel id:

| event | payload | when |
|---|---|---|
| `DialBranch` | `{leg_id, leg_sip_call_id, target, aor}` | a phone's INVITE was built (the later phones of a sequential group included) |
| `ChannelStateChange` | `{state:"ringing"\|"progress", code, early_media, sdp?, leg_id, leg_sip_call_id, target, aor}` | a phone sent a 1xx, as a plain originate reports its callee's, naming the phone |
| `DialBranchFailed` | `{leg_id, leg_sip_call_id, target, aor, code, reason, cause}` | a phone ended without answering: `rejected`, `timeout`, `cancelled` (another answered, or the group ended) or `unsent` |
| `DialAnswered` | `{leg_id, leg_sip_call_id, target, aor, code}` | a phone answered and won |
| `ChannelStateChange` | `{state:"answered", code, sdp?}` | right after `DialAnswered`, as for a plain originate |
| `StasisEnd` | `{reason, code, response}` | nobody answered: `rejected` with the best of the phones' statuses (RFC 3261 §16.7 step 6), `ring timeout` (408), `cancelled` (487), `unsent`, or `media_failed` when the winner's media could not be anchored |

While the phones ring, the channel is bound to the group: an event's `call_id`
and `sip_call_id` carry the `group_id`, since no single dialog is the call yet,
and each leg's own Call-ID is in the payload as `leg_sip_call_id`. From
`DialAnswered` on, the channel **is** the winning phone's call — its envelope
carries that leg's own ids, and every verb works on it exactly as on a plain
originate's channel. `hangup` while the phones ring CANCELs every one of them,
and so does losing the controller connection past its grace window under
`on_lost: "hangup"`. `drop` is refused (`invalid_state`) while they ring: siphon
is their caller, so there is no response to withhold, and the INVITEs would be
left ringing.

In-process, the same primitive is
[`b2bua.originate(...)`](call.md#placing-a-call-b2buaoriginate), which returns the
new leg's SIP Call-ID and drives the ordinary `@b2bua.on_answer` / `on_failure` /
`on_bye` handlers.

## Joining two legs: `bridge`

`originate` gives a controller a second call. `bridge` is what connects it to
the first — the primitive under callback-and-connect, an attended hand-off, and
a controller-driven transfer:

```json
{ "id":"c-9", "type":"command", "module":"sip", "verb":"bridge",
  "target": { "channel": "ch_caller" },
  "args": { "with": "cb-7f3a", "on_peer_hangup": "hangup" } }
```

```json
{ "id":"c-9", "type":"reply", "status":"ok",
  "result": { "channel":"ch_caller", "with":"cb-7f3a", "call_id":"<uuid>",
              "peer_call_id":"<uuid>", "anchored":true,
              "on_peer_hangup":"hangup", "profile":null, "state":"bridging" } }
```

**Both legs must be yours.** The target channel is resolved and
ownership-checked by the substrate; `args.with` is checked the same way here, so
one application can never join another's call to its own (`forbidden`).

**The target is the anchor.** It is the leg that keeps its media session — its
ports, and anything still attached to them. The `with` leg joins the anchor's as
the second party, and its own session is deleted once the bridge forms. Which
one you address is therefore a real choice, not a formality.

**Which profile shapes which leg.** The media engine produces two descriptions
in a bridge: the offer the `with` leg is re-INVITEd with, and the answer the
anchor is re-INVITEd with. Without `profile`, each is shaped by the profile of
the party it goes to — the `with` leg's offer by the profile that leg was
anchored with (an `originate {media: true, profile}`, or the phone of a bridge
dial), the anchor's by the anchor's own — so an SRTP phone joined to a
plain-RTP caller is offered SRTP and the caller keeps plain RTP. A `with` leg
with no media session of its own is offered what the anchor's profile
describes. `profile` names **one profile for the pair** instead, the way one
profile describes both parties of a connecting dial: its `offer` half shapes
what the `with` leg gets and its `answer` half what the anchor gets (the
built-in `rtp_to_srtp`, for example, offers the `with` leg `RTP/SAVP` and
answers the anchor `RTP/AVP`). A profile that asks for `received_from` pins each
party's media ingress to that party's own signalling source. An unknown
profile, or one that is not a non-empty string, is `bad_request` with
`error.details: {verb: "bridge", argument: "profile", reason:
"unknown_profile" | "invalid_value"}`, and nothing is touched. The reply echoes
the `profile` it used (`null` for none).

**Both legs get re-offered, and in that order.** siphon is a B2BUA, so each leg
is its own offer/answer context (RFC 3264 §8) and siphon is the offerer on both
— the two parties never share a dialog and neither ever offers to the other. A
bridge is two RFC 3261 §14 re-INVITEs run back to back: the `with` leg first,
carrying the anchor's current media, then the anchor carrying the answer that
came back. The `with` leg goes first because that is the order in which a
failure costs least — a peer that answers `488` leaves the anchor untouched and
both calls exactly as they were, media included (see below).

**The reply is the local action, not the outcome.** It comes back once the media
has been re-pointed and the first re-INVITE is on the wire. The verdict arrives
as an event, and on **both** channels, because either party can refuse:

| event | payload | when |
|---|---|---|
| `ChannelBridged` | `{peer_call_id, peer_sip_call_id, role:"anchor"\|"peer", anchored}` | both legs answered their re-INVITE — the media meets |
| `BridgeFailed` | `{stage:"offering_peer"\|"offering_anchor", code, peer_sip_call_id}` | a leg refused. At `offering_peer` both calls are left as they were, media sessions included. At `offering_anchor` the anchor is too, but the `with` leg had already accepted the pair's media, which is now released: it is up and owned with no audio until it is bridged again or hung up |
| `ChannelUnbridged` | `{peer_call_id, peer_sip_call_id, reason}` | this leg is parted **and** held — its hold offer has been answered. That is the point at which bridging it again is safe |

**Media attachments come off first, and the teardown is confirmed.** An
announcement still playing on a leg *replaces that leg's outgoing audio*, and a
WebSocket bridge makes the engine the far side of it — either one still live
when the bridge forms is one-way audio. So every attachment on both legs is torn
down before anything is re-pointed, each step awaited and its reply checked
against the engine. A step the backend refuses fails the command rather than
forming half a bridge. Each teardown runs only where there is something to tear
down — the detach where a tee is attached, the stop where siphon started a
prompt — because firing them blind makes the engine reject a command it had
nothing to do, into the counter that means siphon sent it something wrong.

**Re-negotiation, not replacement.** An anchor that is already relaying between
two parties (a pair that was bridged, unbridged and joined again) is renegotiated
with `reoffer` on the call-id it already holds, so its ports and everything on
them survive. A repeat `offer` there would be a *replacement* on the native
backend. An anchor the engine answered itself (`answer_local` — which is how
every controller-owned leg starts, both `handover(answer=True)` and
`originate(media=true)`) has one party and no far leg, and the engine refuses an
`answer` on it; that pair is therefore offered onto a **fresh** engine call-id.

**Nothing is taken away until the peer says yes.** The fresh session is built
beside the two legs' own sessions, not in their place. Both stay on the engine,
and both legs' media verbs keep addressing them, until the bridge forms: only
then are the two single-party sessions deleted and the anchor moved onto the
pair's (the store key stays the leg's SIP Call-ID, so every media verb still
resolves). A bridge that fails deletes only the fresh session, so a caller whose
bridge was refused can still be played to, rung back and recorded, and can be
bridged again. A leg that hangs up while its bridge is forming takes the fresh
session with it.

**A re-offer on a formed bridge is relayed to the other leg.** A hold, a
resume or any other re-INVITE or UPDATE carrying SDP on either leg is passed
to the other leg as a re-INVITE (or UPDATE) of siphon's own, through the pair's
media session, and the other leg's answer comes back as the 200. Each party
keeps getting the media it was bridged with: the `with` leg's SDP is shaped as
its bridge offer was, the target's as its bridge re-INVITE was, whichever of
them re-offers, so a held SRTP phone is still offered SRTP and a held
plain-RTP caller is still answered plain RTP. A refusal from the other leg goes
back to the sender with the same status, and the pair's session is put back
where it was. An offer that crosses one still being relayed, on either leg, is
refused `491` (RFC 3261 §14.1). A re-INVITE or UPDATE without SDP is a session
refresh and is answered at once with the session in force, without disturbing
the other leg. A leg that hangs up mid-relay has the other's pending request
answered `487`, and one the other leg never answers is answered `408`. The
`with` leg still has no media session of its own once bridged: media verbs
address the pair through the target.

**`unbridge` parts without ending.** Both legs stay answered, owned and
addressable, and are put on hold: siphon re-offers each `a=sendonly` (RFC 3264
§8.4; RFC 6337 §3.1 prefers that to the `c=0.0.0.0` of RFC 2543, and §5.1 warns
against it). Ending both would make `unbridge` indistinguishable from two
`hangup`s and throw away the state the controller wanted to keep. A later
`bridge` re-offers `sendrecv`. The reply says the hold offers are on the wire
(`state: "unbridging"`); the `ChannelUnbridged` on each leg says that leg is
parted and held. Wait for it before bridging again, or the new bridge collides
with the hold's own re-INVITE and is refused `invalid_state` (RFC 3261 §14.1).

**When one leg hangs up.** `on_peer_hangup` decides, and it is fixed when the
bridge is formed:

- `"hangup"` (default) — the survivor goes too. A bridged pair behaves like one
  call, so when one party leaves the other has nobody to talk to.
- `"hold"` — the survivor stays up, held and still owned, and gets a
  `ChannelUnbridged{reason: "peer_hangup"}`. Use it for a supervisor or an
  attended hand-off, where the controller has somewhere else to send it. Note
  that if the survivor was the `with` leg of an anchored bridge, the engine
  session went with the anchor: it is still a live SIP dialog and can be bridged
  again, but it no longer has media of its own for `play` / `stream_start`.

Refusals are typed and separately actionable — the point is that a controller can
tell them apart without parsing prose:

| code | when |
|---|---|
| `bad_request` | no `args.with`, the same channel named twice, an `on_peer_hangup` that is not `hangup` / `hold`, or a `profile` that is unknown or not a non-empty string |
| `not_found` | no such channel, or the call is already gone |
| `forbidden` | the `with` channel belongs to another application |
| `invalid_state` | a leg has not answered, is already bridged, has a re-INVITE outstanding (RFC 3261 §14.1 glare), or carries no media description; and for `unbridge`, a leg that is not bridged |
| `unsupported_verb` | the configured media backend refused one of the bridge's media steps |
| `unavailable` | the B2BUA is not running, or the media backend failed |

### `dial` — ring while the caller waits

```json
{ "verb": "dial", "target": { "channel": "ch_caller" },
  "args": { "targets": [ {"aor": "sip:204@pbx.example"},
                         {"uri": "sip:+15550177@trunk.example", "next_hop": "sip:192.0.2.9:5060"} ],
            "strategy": "parallel", "timeout": 20,
            "from": "sip:+15550100@trunk.example", "from_display": "Example Ltd" } }
```

Rings the targets as B-legs of the caller's call while the caller stays
**unanswered** and this app keeps the channel. Provisional responses and early
media reach the caller as they do for a script's `call.fork`; the first 2xx
answers the caller with the winner's SDP and the pair becomes an ordinary
two-leg B2BUA call, with the app still owning it.

A failure or a timeout arrives as `DialFailed {code, reason, timed_out, branches}` with
the caller **still ringing and still parked**. A timeout is `code: 408`, except
on a `sequential` dial whose last target never sent a 101-199: nothing rang, and
it is `503`. Nothing is forwarded to it, so
the app decides what happens next: dial somewhere else on the same channel,
answer into voicemail, or reject with its own code. That is the difference from
[`route`](#route), which hands the call back to siphon — the app gets
`StasisEnd{reason: routed}` and loses it, so "ring the extension, then
voicemail" is not expressible with `route`.

**Every branch is named.** Each B-leg is its own SIP dialog, on a Call-ID siphon
generates, so nothing on the wire ties it to the caller's call. The events do:
each branch is named when its INVITE is built (every fork branch, and each
attempt of a `sequential` hunt when the hunt places it), and named again with
its outcome. A branch is identified by `leg_id`, siphon's id for the B-leg,
stable across a 401/407 or 422 retry of that leg, and `leg_sip_call_id`, the
Call-ID its INVITE carries. The pair follows `ChannelBridged`'s
`peer_call_id` / `peer_sip_call_id`; the bare `sip_call_id` on the frame stays
the caller's own.

| event | payload | when |
|---|---|---|
| `DialBranch` | `{leg_id, leg_sip_call_id, target, aor?}` | a branch was created; its INVITE goes out next |
| `DialBranchFailed` | `{leg_id, leg_sip_call_id, target, aor?, code, reason, cause}` | a branch ended without answering. `cause` is `rejected` (the far end's final non-2xx, `code`/`reason` its own), `timeout` (`408`, it rang out), `cancelled` (`487`, siphon CANCELled it: another branch answered, a `6xx` ended the fork, or the caller hung up) or `unsent` (`503`, the INVITE never reached the transport) |
| `DialAnswered` | `{leg_id, leg_sip_call_id, target, aor?, code}` | this branch answered; sent before the branches it beat are reported `cancelled` |
| `DialFailed` | `{code, reason, timed_out, branches, unsupported?}` | nobody answered. `branches` lists every branch the dial rang as `{leg_id, leg_sip_call_id, target, aor?, code, reason, cause}`. `unsupported` is present only when the dial was refused before any branch was rung (see below) |

Each branch is reported once. A second `dial` on the same channel starts a
fresh list, so its `DialFailed` carries only its own branches.

**A caller that requires what no branch can honour.** When the caller's INVITE
lists an option tag in `Require` that this call cannot honour under its header
policy, no B-leg could ever connect it (RFC 3261 §8.2.2.3), and a controller
cannot change that policy. The dial is refused before anything is rung:
`DialFailed` arrives with `code: 420` (`reason: "Bad Extension"`), or `494`
(`"Security Agreement Required"`) when one of the tags is `sec-agree`,
which is hop-by-hop, `timed_out: false`, an empty `branches` since nothing rang, and `unsupported`, the
array of the tags refused, in the order the INVITE listed them. Unlike every
other `DialFailed`, the caller does **not** stay parked: siphon answers it with
that same `420` (carrying the `Unsupported` header §8.2.2.3 requires) or `494`,
and the channel ends with `StasisEnd`.

Every branch event, and each `DialFailed.branches` entry, also carries `aor`
when the branch was dialled at a contact an `{aor}` target resolved to: the
registered AoR (its canonical key) the branch rang, so `DialAnswered.aor` is the
phone that picked up. It is absent for a URI dialled as written, even one that
happens to be a registered contact — only an `{aor}` target says whom the branch
was dialled for.

A target is a URI string, `{uri, next_hop?, headers?}`, or `{aor}`, and either
object form may also carry `from?`, `from_display?`, `p_asserted_identity?` and
`privacy?` for that branch alone. Either form may also carry `to?`, the called
party the branch is addressed to, on every contact an `aor` forks to (see
[naming the called party](#naming-the-called-party)). An `aor`
resolves against the registrar and forks to **every** registered contact, each
over that contact's own captured flow and Path route set — which is the only way
to reach a phone registered over TCP, TLS or WSS behind NAT, since such a
contact is reachable only on the connection it registered over. An AoR nobody
has registered contributes no branch; `dial` answers `not_found` when no target
yields one.

A target's identity overrides the dial's field by field, the same precedence
its headers already use, so a target naming only a `from` still inherits the
dial's `privacy`. This is what a hunt across two carriers needs: the number a
carrier will accept is a property of that carrier, not of the call, and
presenting another carrier's number leaves it challenging the INVITE however
correct the digest is. A target naming nothing presents the dial's identity.

`strategy` is `parallel` (default) or `sequential`; `timeout` is the ring
timeout in seconds (default 30). Dialling a call that is already answered is
`invalid_state` — answering first is what the verb exists to avoid, since it
starts billing before anyone picks up and denies the caller the callee's own
ringback. That refusal carries
`error.details: {"verb": "dial", "reason": "already_answered", "call_state": "answered"}`,
where `call_state` is the state the call was found in, so a controller can tell
it from any other `invalid_state` without reading the message. A caller the app answered on purpose, to play it prompts first, is
what `on_answer: "bridge"` is for.

### `dial {on_answer: "bridge"}` — ring phones for an answered caller

```json
{ "verb": "dial", "target": { "channel": "ch_caller" },
  "args": { "on_answer": "bridge", "targets": [ {"aor": "sip:204@pbx.example"} ],
            "strategy": "parallel", "timeout": 20, "ringback": "ringback_eu" } }
```

The end of every IVR flow: greeting, menu, then ring the department. The caller
is already answered and anchored on the media engine (`answer {anchor: true}`),
which is what let the app `play` to it, so a connecting `dial` refuses it.
`on_answer` says what happens when a phone picks up:

- `"connect"` (the default) — today's dial: the phone's answer answers the
  caller. Refused on an answered call, as above.
- `"bridge"` — accepted **only** on an answered caller with an anchored media
  session. Each phone is rung as a call siphon places itself (every contact of
  an `{aor}` over its own flow and Path, a URI as written, one phone per leg),
  and the one that answers first is **bridged** to the caller the way the
  [`bridge`](#joining-two-legs-bridge) verb joins two channels, with its
  default `on_peer_hangup: "hangup"` (when either party hangs up, the other is
  hung up too). The caller's own dialog is not touched until the bridge
  re-INVITEs it.

The targets, `strategy` (`parallel`, `sequential`), per-target `next_hop` and
`headers`, the dial's `headers`, and every identity argument — `from`,
`from_display`, `p_asserted_identity`, `privacy`, on the dial and per target —
apply as they do for a connecting dial. A leg that names no identity shows the
phone the **caller's** `From`, display name included; a named one is shaped by
the same rules as above. Unlike a connecting dial, none of the caller's other
INVITE headers reach the phones: each leg is a fresh call. `timeout` is how long
each phone rings; the dial as a whole rings for `timeout` (parallel) or
`timeout` × the number of phones (sequential). `profile` names the media profile
each phone is anchored with, the caller's own by default. It describes the
**phone**, not the pair: it shapes the phone's answer when it picks up and the
bridge's offer to it, while the caller is re-INVITEd with its own profile's
answer half. So a caller answered with plain RTP and a dial naming an SRTP
profile join an SRTP phone to a plain-RTP caller, each on the media it was
anchored with.

**Ringback.** `ringback` is a tone preset or cadence (`"ringback_eu"`,
`"425/1000,0/4000*inf"`, anything [`play {tone}`](#phase-1-verb-set) takes),
`true` for the default, or `false` for none; it defaults to `"ringback_eu"`.
Any other value is `bad_request`, and naming one on a connecting dial is too.
The ringback starts on the first `180`-`183` from any phone — a phone is
actually alerting (RFC 3960) — not when the dial starts, and plays on the
caller's anchor through the same engine path as `play {tone}`. A playback the
app started is never talked over: when a phone alerts while a prompt still
plays, the ringback waits for that prompt's `PlayFinished` and starts only if
the phones are still ringing. (That needs an engine that reports a playback's
end, siphon-rtp; with rtpengine a prompt that ends on its own is not seen to
end, so the ringback is held until the dial ends.) It stops before the bridge
re-points the caller's media, before `DialFailed`, and with the caller when it
hangs up; when a bridge fails and phones still ring, it starts again, on the
caller's own media session, which a failed bridge never touches. Its
`PlayStarted` and `PlayFinished` carry `origin: "ringback"`, so
the app can tell them from its own. With `ringback: false` the caller hears
whatever the app leaves playing — its own tone or music on hold.

A phone's early media is **not** relayed to the caller in this version: the two
are not joined until one answers, and the ringback covers the wait.

**An answer is kept only once its phone is bridged.** When a phone picks up it
is ACKed and the bridge to it starts, but every other phone keeps ringing until
`ChannelBridged`; only then are they CANCELled. A phone that answers while a
bridge is in motion waits as a standby, ACKed and silent. When a bridge fails —
the phone rejects the bridge's re-INVITE, or the bridge cannot start (the caller
has a re-INVITE of its own in flight) — that phone is hung up with
`Reason: Q.850;cause=41`, reported as `DialBranchFailed` with cause
`bridge_failed`, and the dial goes on: the standbys are bridged next in the
order they answered, the phones still ringing ring on, and a sequential dial
rings its next target. When the bridge forms, every standby is hung up
(`Reason: Q.850;cause=16`) and reported, with the phones still ringing, as
`DialBranchFailed` with cause `cancelled`. The dial's deadline still applies:
when it passes, the phones still ringing are CANCELled, but an answer already
being bridged is seen through. `DialFailed` comes only once nothing is left.

**Events**, all on the caller's channel:

| event | payload | when |
|---|---|---|
| `DialBranch` | `{leg_id, leg_sip_call_id, target, aor?}` | a phone's INVITE goes out |
| `PlayStarted` | `{source: "tone", origin: "ringback", play_id?, duration_ms?}` | a phone is alerting and the ringback started |
| `DialBranchFailed` | `{leg_id, leg_sip_call_id, target, aor?, code, reason, cause}` | a phone ended without being kept: it never answered, it was CANCELled or released once another was bridged (`cancelled`), or it answered and its bridge failed (`bridge_failed`) |
| `BridgeFailed` | as for `bridge` | a bridge to a phone that answered failed. On the caller's channel only, since the phone was never given one; `stage: "setup"` with a `reason` when the bridge never started |
| `DialAnswered` | `{leg_id, leg_sip_call_id, target, code, aor?, channel}` | the phone that was **bridged**, sent once, when the bridge forms and just before `ChannelBridged`: an answer is not reported until it is kept. `channel` is a channel siphon minted for it, registered to this app and connection with the caller's `on_lost` policy (`null` when that channel has no live owner); the phone's own events follow on it |
| `ChannelBridged` | as for `bridge`, on both channels | the bridge formed |
| `DialFailed` | `{code, reason, cause, timed_out, branches}` | nobody answered; the ringback is already stopped, and nothing was sent to the caller. `branches` entries are `{leg_id, leg_sip_call_id, target, aor?, code, reason, cause}` |

`cause` on `DialFailed` says how the dial ended: `rejected`, `ring timeout`,
`unsent`, `bridge_failed`, the `reason` a [`cancel_dial`](#cancel_dial--stop-a-dial-and-keep-the-caller)
named (`cancelled` when it named none), or `caller_hangup` when the caller went
away while the phones rang.
In that last case every phone is CANCELled (RFC 3261 §9.1) and `DialFailed`
precedes the caller's `StasisEnd`. After `DialFailed` the caller is still
answered and owned: play the voicemail prompt, or dial again.

A phone that hangs up while its bridge is in motion takes the caller with it,
as a bridged party does (`on_peer_hangup: "hangup"`); the fallback covers a
bridge that is refused or cannot start, not a phone that leaves.

Refused, each with `error.details` `{verb: "dial", reason, …}`:

| code | `reason` | when |
|---|---|---|
| `bad_request` | `unknown_value` (`argument: "on_answer"`) | `on_answer` is not `"connect"` or `"bridge"` |
| `bad_request` | `invalid_value` / `requires_bridge` (`argument: "ringback"`) | `ringback` is not a non-empty string or a boolean; or it is named on a connecting dial |
| `invalid_state` | `already_answered` (with `call_state`) | a connecting dial (no `on_answer`, or `"connect"`) on an answered caller |
| `invalid_state` | `not_answered` (with `call_state`) | `bridge` on a caller that is not answered |
| `invalid_state` | `not_anchored` | `bridge` on an answered caller with no media session on the engine |
| `invalid_state` | `already_bridged` | the caller is already bridged |
| `invalid_state` | `dial_in_progress` | the caller already has phones ringing for it |
| `invalid_state` | `dial_cancelled` | a `cancel_dial` arrived while the dial was being set up: no phone was rung |
| `not_found` | `call_gone` | the caller is gone |

### `cancel_dial` — stop a dial and keep the caller

```json
{ "verb": "cancel_dial", "target": {"channel": "ch1"}, "args": { "reason": "gave_up" } }
```

A dial ends on its own when a phone answers, when every phone fails, or when
the ring timeout passes. `cancel_dial` is the fourth way, and the only one the
application chooses: every phone still ringing is CANCELled (RFC 3261 §9.1) and
the caller is left exactly as the dial found it, still owned by this channel
and free to be dialled for again.

That is what tells it from the two verbs that look similar. `hangup` ends the
caller as well. Letting the timeout run keeps the phones ringing until it does,
and a phone that answers in that window is connected to a caller the
application has already sent somewhere else.

- A **bridging** dial (`on_answer: "bridge"`): each phone is reported by
  `DialBranchFailed` with cause `cancelled`, the ringback is stopped, and the
  dial ends in `DialFailed {code: 487, reason: "Request Terminated", cause,
  timed_out: false}`. `cause` is the `reason` given here, `cancelled` when none
  is, so a handler can tell its own cancel from a dial that failed by itself.
  The caller stays answered and anchored.
- A **connecting** dial: each branch is reported by `DialBranchFailed` with
  cause `cancelled`, a sequential hunt's remaining targets are dropped, and the
  dial ends in `DialFailed {code: 487, timed_out: false}`. The caller stays
  unanswered and parked, with no ring deadline left to fail it.

The reply is `{channel, state: "cancelled", on_answer}`. Refused, each with
`error.details` `{verb: "cancel_dial", reason}`:

| code | `reason` | when |
|---|---|---|
| `invalid_state` | `no_dial_in_progress` | nothing is ringing: the dial already ended, or none was issued |
| `invalid_state` | `dial_answered` | a phone has answered and its bridge to the caller is in motion. The caller's media is being pointed at that phone, so it cannot be released without taking the caller with it; the outcome arrives as `DialAnswered` or `BridgeFailed`, and after a `BridgeFailed` the dial rings on and can be cancelled |
| `not_found` | `call_gone` | the call is gone |
| `bad_request` | — | `reason` is not a non-empty string |

### Presenting an identity

`from`, `from_display`, `p_asserted_identity` and `privacy` are the same
identity arguments [`originate`](#phase-1-verb-set) takes, and they apply to the
whole dial: every branch of a fork, every attempt of a sequential hunt.

They matter because a B-leg's `From` is **framework-managed** — siphon swaps in
a fresh dialog tag and, for topology hiding, rewrites the host to its own
advertised address. Without these arguments the B-leg presents the caller's own
`From`, which on a call out to a trunk is the internal extension. A carrier that
looks its account up by the `From` user does not recognise it, so it challenges
the INVITE and keeps challenging however correct the digest is, and
`P-Asserted-Identity` alone does not fix it because that is not what such a
carrier keys on. An injected `headers: {"From": …}` cannot fix it either: the
host is overwritten after the fact, and a `From` written without its tag drops
the mandatory dialog tag (RFC 3261 §8.1.1.3), which only shows up later, on the
ACK.

- `from` replaces the whole URI and **pins the host**, opting this leg out of
  the `From` host rewrite. A target's own `from` pins that target's host, so
  each carrier in a hunt sees its own domain.
- `from_display` sets the display name; `""` removes it. Naming a `from` without
  a `from_display` drops the caller's, rather than presenting `"203"` beside the
  number that replaced it.
- `p_asserted_identity` is injected **after** the header policy, so a preset that
  strips `P-*` at a trust boundary cannot silently drop an identity the
  controller named. It goes out as a `name-addr` (`<sip:...>`) whether it was
  given bare or in brackets; a `sip:` and a `tel:` identity may be given
  together, comma-separated (RFC 3325 §9.1).
- `privacy: "restricted"` anonymises `From` and asserts `Privacy: id` while
  `p_asserted_identity` keeps the real identity for the trusted next hop
  (RFC 3323 §4.1 / RFC 3325 §7 / TS 24.607). `"allowed"` presents it. Anything
  else is `bad_request` — guessing at a privacy setting is how identities leak.

A `from` that is not a SIP URI, on the dial or on any target, is `bad_request`,
refused before any phone rings.

The caller's `Remote-Party-ID`, which the default header policy copies, follows
the identity: a branch presenting a `from` of its own, or withheld with
`privacy: "restricted"`, carries none, since the caller's would assert the
identity the branch replaced or withheld. A `Remote-Party-ID` the controller
names in a branch's `headers` goes out as written.

### Naming the called party

`uri` is the B-leg's **Request-URI**. Its `To` is a separate header, and by
default siphon builds it from the **caller's** `To`: the tag dropped and the
host and port replaced with the target's, the **user part kept**. That is right
for a forward, where the B-leg reaches the party the caller asked for, and wrong
for a divert (call-forward, follow-me, overflow to a mobile), where the call goes
to a different number. The R-URI then names the new party while `To` still names
the number the caller dialled, so the two diverge:

```
INVITE sip:+15550199@trunk.example SIP/2.0     <- the divert target (uri)
To: <sip:+15550100@trunk.example>              <- the number originally dialled
```

A next hop that routes on `To` rather than the R-URI serves that as a fresh call
to the original number and can send it straight back. Each pass looks like a new
call to it, so a `Diversion` counter never climbs and the loop detection it
exists for never fires.

A target's `to` sets the B-leg's `To` URI outright, as `<to>` with no tag (RFC
3261 §8.1.1.2), on that branch alone: neither the host rewrite nor
`call.set_to_host()` touches it. siphon records it as the leg's dialog `To`, so
its own later requests on that dialog (BYE, re-INVITE, session refresh) are
addressed the same way. A `headers: {"To": …}` override reaches only the INVITE
and is not a substitute. It works on every strategy: each branch of a fork, each
attempt of a sequential hunt, and each phone of an `on_answer: "bridge"` dial.

```json
{"verb": "dial", "args": {"targets": [
  {"uri": "sip:+15550199@trunk.example",
   "to":  "sip:+15550199@trunk.example",
   "headers": {"Diversion": "<sip:+15550100@pbx.example>;reason=unavailable;counter=1"}}
]}}
```

A `to` that is not a SIP URI is `bad_request`, refused before any phone rings.

### Anchoring the media

`profile` optionally selects a configured media profile and anchors both legs
through the media engine. For example, plain RTP from a trunk to a phone that
requires SDES-SRTP uses `"profile": "rtp_to_srtp"`; the reverse direction uses
`srtp_to_rtp`. The profile's `offer` half shapes the SDP sent to the phone and
its `answer` half shapes the SDP sent back to the caller. TLS signalling alone
does not imply SRTP: select the profile from the endpoints' media policy.

A profiled dial requires a caller SDP offer and no pre-existing media anchor. An
unknown profile, missing backend or failed media allocation returns `unavailable`
without sending an INVITE or answering the caller. Invalid profile values return
`bad_request`. Without `profile`, the existing unanchored behaviour is unchanged.
A failed profiled dial releases its media session before `DialFailed`, preserving
the original caller SDP for a later voicemail answer.

A profiled dial may fork. **One** allocation serves the whole dial: every branch
is offered the same anchored SDP, exactly as a forking proxy offers one body to
every branch, and whichever branch sends SDP is answered against it — the media
engine re-points the far side of the relay on each answer, so the last SDP to
arrive is what the caller hears and the `2xx` settles it on the branch that won
(RFC 3261 §16.7). A sequential hunt re-uses that one allocation across its
attempts rather than re-anchoring per attempt. What one allocation cannot do is
give two *simultaneously* ringing branches separate early-media paths; that needs
one allocation per branch. In practice phones ring with a `180` that carries no
SDP, so this only shows up on a fork where two branches both open early media —
the second takes the caller's ear from the first.

A carrier-delivered call to a ring group is the case that needs a profile most:
the carrier hands over plain RTP at a routable address and every phone answers
from an address on its own LAN, so without the relay in the middle the two ends
cannot reach each other.

siphon does not retry a `491 Request Pending`. It reports the glare and leaves
the pairing to the controller, which by then may want a different one.

On a call with **no second leg** — one siphon answered itself and anchored on
the media engine, which is what an IVR, a queue or a voicemail box is — a
re-INVITE or an UPDATE from the endpoint is answered here, from the engine. A
hold arrives as a `sendonly` re-offer and is answered `recvonly` (RFC 3264
§6.1); an offerless refresh is answered with the leg's current media, because
RFC 3261 §13.2.1 makes the `2xx` to an offerless INVITE carry the offer. A call
with no media backend takes a `200` with no body. Nothing is forwarded, because
there is nowhere to forward it.

**Known limitation.** While a pair is **bridged**, a re-INVITE *from* one of the
endpoints is still answered `491 Request Pending` rather than relayed across the
bridge.

In-process, the same primitives are
[`b2bua.bridge(...)` / `b2bua.unbridge(...)`](call.md#joining-two-calls-b2buabridge).

## Swapping a party: `replace_peer`

`bridge` joins two calls the app owns. `replace_peer` swaps one party of a single
answered call for somebody new, with no REFER anywhere — the app decides, the way
an IVR decides where a caller goes next, or a controller hands a call from an AI
to a human.

siphon has always been able to do this; it was reachable only when a remote
endpoint asked, by sending a REFER that siphon terminated. The verb runs that
same machinery on the app's say-so: dial the target as a new leg on the call,
re-anchor the surviving party's media onto it, and when the target answers
promote it into the surviving pair and BYE the leg it replaced.

```jsonc
{"type":"command","id":"c9","module":"sip","verb":"replace_peer",
 "target":{"channel":"ch1"},
 "args":{"target":"sip:operator@pbx.example","timeout":45}}
```

**The replaced leg stays up while the target rings.** It is released only once
the target answers, so the surviving party hears ringback instead of dead air,
and a target that refuses or never answers leaves the call exactly as it was.
This is the whole reason to use the verb rather than a `hangup` followed by a
re-INVITE: that sequence silences the caller for the length of the ring, and it
leaves the call's own state behind — no `on_bye`, no CDR, no charging stop, no
media release.

`target` is a URI string, `{uri}` or `{aor}`, and `from`, `from_display`,
`p_asserted_identity`, `privacy` and `headers` shape the new leg, all exactly as
for [`accept_refer`](#an-inbound-refer-on-a-controlled-call): an AoR is dialled
over the flow its phone registered on, and one with several registered contacts
rings them all. The first to answer is the party that replaces the leg, and the
rest are CANCELled. The replaced leg stays up through all of it, and is released
only when one of them answers.

`replace_a_leg` picks the direction. Omitted or `false` replaces the callee and
keeps the caller; `true` does the reverse. `profile` names the media profile for
the pair this creates, and is required when the call is anchored with a
direction-bound one, whose answer half was written for the party that is
leaving. `timeout` bounds the ring in seconds; `0` means no ring policy, leaving
only siphon's own guard against a target that answers nothing at all.

**The reply is the local action, not the outcome** — `{channel, replacement:
"dialing", target}`, which means the INVITE is on the wire and nothing more. An
app that acts on it alone will tear down a call whose replacement is still
ringing. The verdict arrives as an event:

| event | payload | when |
|---|---|---|
| `PeerReplaced` | `{target_sip_call_id, replaced_leg_released, origin}` | the target answered, was promoted into the pair, and the replaced leg was released |
| `ReplaceFailed` | `{status, call_kept, origin}` | the target refused, or never answered (`status: 408`). With several contacts ringing: once, when none of them is left, with the best of their responses |

Branch on `ReplaceFailed.call_kept`: normally the original call is intact and
still has both parties, so another target can be tried on the same channel. It
is `false` only when the leg being replaced had already hung up while the target
was ringing, which leaves the survivor with nobody and the call released.
`origin` is `"siphon"` for this verb and `"refer"` when the same events describe
a REFER-driven transfer.

Refusals are typed the same way as `bridge`'s:

| code | when |
|---|---|
| `bad_request` | no `args.target`, a target or `next_hop` that will not parse, a nonsense `timeout`, or a target siphon cannot route to |
| `not_found` | no such channel, or the call is already gone |
| `invalid_state` | the call has not answered, has no peer leg to replace, or already has a replacement in flight — all worth retrying later |
| `unavailable` | the B2BUA is not running |

In-process, the same primitive is
[`b2bua.replace_peer(...)`](call.md#swapping-a-party-mid-call-b2buareplace_peer).

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

The complete wire reference, both connection modes end to end, and two
low-level example clients (one Python, one TypeScript) that drive calls with no
SDK live in the repository:

- Protocol + example clients:
  [`examples/remote_control/`](https://github.com/siphon-project/siphon-sip/tree/main/examples/remote_control)
- SDK sources:
  [`siphon-control-sdk/`](https://github.com/siphon-project/siphon-sip/tree/main/siphon-control-sdk)
  (`siphon-control-proto` is the shared DTO crate — the single source of truth
  for the frames above)
