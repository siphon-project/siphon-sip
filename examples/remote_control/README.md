# Remote-control client examples (experimental)

Two small external applications — one Python, one TypeScript — that drive live
calls over siphon's control WebSocket. A B2BUA script hands a call over with
`call.handover("ivr-app")` (the ARI *Stasis* model); the out-of-process app then
answers and hangs it up. Calls that are not handed over are unaffected.

This is a proof-of-concept: the control plane currently exposes two verbs,
`answer` and `hangup`. play / dtmf / bridge / transfer / originate arrive in later
phases over the same protocol and envelope.

## Wire protocol

Single WebSocket per app, JSON text frames, request-id correlated:

```
command  (client → siphon)  { "id":"c-1", "type":"command", "verb":"answer",
                              "target":{"channel":"<id>"}, "args":{} }
reply    (siphon → client)  { "id":"c-1", "type":"reply", "status":"ok",
                              "result":{...} }        // or "status":"error", "error":{code,message}
event    (siphon → client)  { "type":"event", "event":"StasisStart",
                              "channel":"<id>", "app":"ivr-app", "payload":{...} }
```

The connection authenticates with `Authorization: Bearer <token>` on the WebSocket
upgrade (a bad/missing token is rejected `401` before the socket opens), then sends
a first `hello` command whose `app` must match the token's configured application.

## siphon configuration

Add a `control:` block to `siphon.yaml`:

```yaml
control:
  listen: "127.0.0.1:9092"        # loopback for local testing
  event_queue_depth: 1024          # per-connection bounded event queue (optional)
  apps:
    - name: "ivr-app"
      token: "${IVR_APP_TOKEN:-changeme-dev-token}"
```

Hand matching calls over from the B2BUA script:

```python
from siphon import b2bua

@b2bua.on_invite
async def route(call):
    if call.to_uri.endswith("@ivr.example.com"):
        call.handover("ivr-app")     # → external control
    else:
        call.dial(call.ruri)         # normal B2BUA
```

## Run the Python client

```bash
pip install "websockets>=14"
IVR_APP_TOKEN=changeme-dev-token python control_client.py
```

## Run the TypeScript client

```bash
npm install
IVR_APP_TOKEN=changeme-dev-token npm start
```

Both accept the same environment overrides:

| variable              | default                              |
| --------------------- | ------------------------------------ |
| `SIPHON_CONTROL_URL`  | `ws://127.0.0.1:9092/control/ws`     |
| `SIPHON_CONTROL_APP`  | `ivr-app`                            |
| `IVR_APP_TOKEN`       | `changeme-dev-token`                 |

Place a call to a handed-over destination and the client will log `StasisStart`,
answer the call, hold it briefly, then hang up.
