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
| `answer` | sip | `{code, reason?, body?, content_type?}` | UAS 2xx to the parked A-leg |
| `progress` | sip | `{code, reason?, body?, content_type?}` | 1xx / early media |
| `reject` | sip | `{code, reason?}` | final non-2xx + tear down |
| `hangup` | sip | `{reason?}` | BYE an answered call, or reject an unanswered one |
| `refer` | sip | `{to, replaces?}` | in-dialog REFER on the A-leg |
| `set_header` / `get_header` | sip | `{name, value?}` | on the stored A-leg INVITE |
| `set_var` / `get_var` | — | `{key, value?}` | per-call variables (drain with the call) |
| `resync` | — | — | re-attach + enumerate this app's owned calls |
| `describe` | — | — | list the registered adapters + their verb/event schema |

`play` / `dtmf` / `bridge` / `originate` / media-stream verbs arrive in later
phases over the same envelope.

The complete wire reference, both connection modes end to end, and two
low-level example clients (one Python, one TypeScript) that drive calls with no
SDK live in the repository:

- Protocol + example clients:
  [`examples/remote_control/`](https://github.com/siphon-project/siphon-sip/tree/main/examples/remote_control)
- SDK sources:
  [`siphon-control-sdk/`](https://github.com/siphon-project/siphon-sip/tree/main/siphon-control-sdk)
  (`siphon-control-proto` is the shared DTO crate — the single source of truth
  for the frames above)
