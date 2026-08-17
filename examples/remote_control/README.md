# Remote-control client examples

Two small external applications — one Python, one TypeScript — that drive live
calls over siphon's control WebSocket (ARI/ESL-class) using the official client
**SDKs**. A B2BUA script hands a call over with `call.handover("ivr-app")` (the
ARI *Stasis* model); the out-of-process app then answers, sets a per-call
variable, holds briefly, and hangs up. Calls that are not handed over are
unaffected.

Both examples use the SDK — the official interop path. There is **no manual
frame construction**: the SDK owns the transport, the `hello` handshake,
request-id correlation, and reconnect + `resync`. You write `call.answer()` /
`call.transfer(...)` / `call.hangup()`, exactly as an in-process siphon script
would.

- **Python** (`control_client.py`) uses [`siphon-control`](../../siphon-control-sdk/siphon-control),
  which ships the **inbound-persistent** client.
- **TypeScript** (`control_client.ts`) uses [`@siphon-project/control`](../../siphon-control-sdk/typescript),
  which ships **both** connection modes.

The raw `siphon-control.v1` JSON protocol these SDKs speak (the command / reply /
event envelope, the verb set, the error codes) is documented under the hood in
the control-plane reference at <https://siphon-sip.org/reference/control-plane/>
— you do not need it to use the examples.

## Connection modes

- **Outbound per-call-connect (the documented default).** The app runs a
  WebSocket **server**; siphon dials it once per handed-over call and the
  accepting socket owns that call (the FreeSWITCH-outbound model). There is **no
  `hello`** — the first frame the app receives is `StasisStart`. Use this for
  multi-pod / autoscaled controllers: siphon always dials *out*, so the "which
  pod owns the call" affinity problem cannot arise. In the TypeScript SDK this is
  `SipServer`.

- **Inbound persistent.** The app is a WebSocket **client** that connects in to
  `control.listen` and owns calls assigned to it (round-robin across the app's
  connections). It sends a first `hello` (whose `app` must match the token's
  configured application) and `resync`s to re-attach its calls after a reconnect.
  This is `SipClient` (TypeScript) / `ControlClient` (Python).

The TypeScript example selects the mode with `SIPHON_CONTROL_MODE`
(`outbound` | `inbound`). The Python SDK ships the inbound-persistent client, so
the Python example is inbound.

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
the WebSocket bridge before handing over, so the app drives an already-connected
channel; it requires the `siphon-rtp` media backend.

## Run the Python client

```bash
# install the SDK:
pip install siphon-control            # once published
# ...or from this repo, into the active venv:
#   cd ../../siphon-control-sdk/siphon-control && maturin develop

IVR_APP_TOKEN=changeme-dev-token python control_client.py
```

## Run the TypeScript client

The example depends on `@siphon-project/control` via a `file:` path to the sibling
package, so it is runnable before the SDK is published. **Build the SDK first**
(its `dist/` is what the `file:` dependency resolves):

```bash
# build the sibling SDK once:
npm --prefix ../../siphon-control-sdk/typescript install
npm --prefix ../../siphon-control-sdk/typescript run build

# then this example:
npm install                           # wires up the file: dependency
# ...once published, this is simply `npm i @siphon-project/control`.

# outbound (default): this app is the server siphon dials
SIPHON_CONTROL_BIND=0.0.0.0:8443 IVR_APP_TOKEN=changeme-dev-token npm start

# inbound: this app dials siphon's control.listen
SIPHON_CONTROL_MODE=inbound IVR_APP_TOKEN=changeme-dev-token npm start

# type-check only
npm run typecheck
```

## Environment variables

| var | default | applies to | meaning |
|---|---|---|---|
| `SIPHON_CONTROL_MODE` | `outbound` | TypeScript | `outbound` (server) or `inbound` (client) |
| `IVR_APP_TOKEN` | `changeme-dev-token` | both | bearer token (must match `control.apps[].token`) |
| `SIPHON_CONTROL_APP` | `ivr-app` | both | app name asserted in `hello` (inbound) |
| `SIPHON_CONTROL_BIND` | `127.0.0.1:8443` | TypeScript outbound | `host:port` this app listens on for siphon's dials |
| `SIPHON_CONTROL_URL` | `ws://127.0.0.1:9092/control/ws` | inbound | siphon's control listener URL |
