# Remote-control client examples (low-level protocol reference)

> **Building a real controller? Use the SDKs, not this.** The supported way to
> drive handed-over calls is the client SDKs, which hide the wire (no manual
> JSON, no request-id bookkeeping, no reconnect loop):
>
> - Python: `pip install siphon-control`
> - Rust: `cargo add siphon-control-client`
>
> See the [control-plane reference](https://siphon-sip.org/reference/control-plane/)
> and [`siphon-control-sdk/`](../../siphon-control-sdk/). The two clients below
> are a **hand-rolled `siphon-control.v1` reference** — read them to build a
> client in a language the SDKs don't cover, or to understand the wire.

Two small external applications — one Python, one TypeScript — that drive live
calls over siphon's control WebSocket (ARI/ESL-class) **without an SDK**. A
B2BUA script hands a call over with `call.handover("ivr-app")` (the ARI *Stasis*
model); the out-of-process app then answers, sets a per-call variable, holds
briefly, and hangs up. Calls that are not handed over are unaffected.

Both clients support **both connection modes** and default to
**outbound per-call-connect**.

## Connection modes

Same JSON-over-WebSocket protocol (subprotocol `siphon-control.v1`) on the
socket in either mode.

- **Outbound per-call-connect (the documented default).** The app runs a
  WebSocket **server**; siphon dials it once per handed-over call and the
  accepting socket owns that call (the FreeSWITCH-outbound model). There is **no
  `hello`** — the first frame the app receives is `StasisStart`. Use this for
  multi-pod / autoscaled controllers: siphon always dials *out*, so the "which
  pod owns the call" affinity problem cannot arise. The app must echo the
  `siphon-control.v1` subprotocol on accept (both example servers do).

- **Inbound persistent.** The app is a WebSocket **client** that connects in to
  `control.listen` and owns calls assigned to it (round-robin across the app's
  connections). It sends a first `hello` (whose `app` must match the token's
  configured application) and can `resync` to re-attach its calls after a
  reconnect.

Select the mode with `SIPHON_CONTROL_MODE` (`outbound` | `inbound`).

## Wire protocol

Single WebSocket per connection, JSON text frames, request-id correlated.
Adapter commands carry `module` (`"sip"`); substrate commands (`hello`,
`resync`, `describe`, `set_var`, `get_var`) omit it.

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
chunk, so your logs join Homer + billing with no mapping table.

## Phase-1 verb set

| verb | module | args | notes |
|---|---|---|---|
| `answer` | sip | `{code, reason?, body?, content_type?}` | send a UAS 2xx to the parked A-leg |
| `progress` | sip | `{code, reason?, body?, content_type?}` | send a 1xx / early media |
| `reject` | sip | `{code, reason?}` | final non-2xx + tear down |
| `hangup` | sip | `{reason?}` | BYE an answered call, or reject an unanswered one |
| `refer` | sip | `{to, replaces?}` | in-dialog REFER on the A-leg |
| `set_header` / `get_header` | sip | `{name, value?}` | on the stored A-leg INVITE |
| `set_var` / `get_var` | — | `{key, value?}` | per-call variables (drain with the call) |
| `resync` | — | — | re-attach + enumerate this app's owned calls |
| `describe` | — | — | list the registered adapters + their verb/event schema |

A command against a dead/unknown call returns a typed `not_found`; a command
targeting another app's call returns `forbidden` — neither ever hangs.
(`play` / `dtmf` / `bridge` / `originate` / media-stream verbs arrive in later
phases over the same protocol and envelope.)

## siphon configuration

Add a `control:` block to `siphon.yaml`:

```yaml
control:
  # outbound per-call-connect (default) — siphon dials the app per call:
  apps:
    - name: "ivr-app"
      token: "${IVR_APP_TOKEN:-changeme-dev-token}"
      per_call_connect: true
      connect_url: "ws://127.0.0.1:8443/siphon"
  # inbound persistent — the app connects in here instead:
  # listen: "127.0.0.1:9092"
  limits:
    event_queue_depth: 1024
    reattach_grace_secs: 10
```

Hand matching calls over from the B2BUA script:

```python
from siphon import b2bua

@b2bua.on_invite
async def route(call):
    if call.to_uri.endswith("@ivr.example.com"):
        call.handover("ivr-app")          # → external control (deferred / hold)
    elif call.to_uri.endswith("@ai.example.com"):
        call.handover("ivr-app", answer=True,   # answer-first (AI-park):
                      ws_uri="wss://ai.example/stream/{call_id}")  # 200 + media to the AI bridge
    else:
        call.dial(call.ruri)              # normal B2BUA
```

`answer=True` (answer-first / AI-park) answers the call and anchors its media to
the `voice_ai` WebSocket bridge before handing over, so the app drives an
already-connected channel; it requires the `siphon-rtp` media backend.

## Run the Python client

```bash
pip install "websockets>=14"

# outbound (default): this app is the server siphon dials
SIPHON_CONTROL_BIND=0.0.0.0:8443 IVR_APP_TOKEN=changeme-dev-token python control_client.py

# inbound: this app dials siphon's control.listen
SIPHON_CONTROL_MODE=inbound IVR_APP_TOKEN=changeme-dev-token python control_client.py
```

## Run the TypeScript client

```bash
npm install

# outbound (default)
SIPHON_CONTROL_BIND=0.0.0.0:8443 IVR_APP_TOKEN=changeme-dev-token npm start

# inbound
SIPHON_CONTROL_MODE=inbound IVR_APP_TOKEN=changeme-dev-token npm start

# type-check only
npm run typecheck
```

## Environment variables

| var | default | applies to | meaning |
|---|---|---|---|
| `SIPHON_CONTROL_MODE` | `outbound` | both | `outbound` (server) or `inbound` (client) |
| `IVR_APP_TOKEN` | `changeme-dev-token` | both | bearer token (must match `control.apps[].token`) |
| `SIPHON_CONTROL_APP` | `ivr-app` | inbound | app name asserted in `hello` |
| `SIPHON_CONTROL_BIND` | `127.0.0.1:8443` | outbound | `host:port` this app listens on for siphon's dials |
| `SIPHON_CONTROL_URL` | `ws://127.0.0.1:9092/control/ws` | inbound | siphon's control listener URL |
