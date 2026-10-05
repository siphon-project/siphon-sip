# siphon-control (Python)

Python client for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class rail for driving
handed-over calls out of process. Built with [PyO3](https://pyo3.rs) over the
async Rust client, so the wire is hidden: no manual JSON, no request-id
bookkeeping.

## Two connection modes

The plane runs in one of two modes; both are exposed here and share the SAME
`@on_call` decorator and the SAME `Call` handle — only the transport differs.

- **Inbound-persistent** (`ControlClient`) — the app dials siphon and holds one
  long-lived socket (does the `hello` handshake). Simplest to reason about; use
  it for development and single-process controllers.
- **Per-call-connect** (`ControlServer`) — *siphon dials the app* per handed-over
  call, so the app is a WebSocket server. Each accepted connection owns exactly
  one call and the first frame is a pushed `StasisStart` (no `hello`). This is
  the documented production default for multi-pod controllers: because the
  accepting socket *is* the call, "the audio lands on the wrong pod" can't
  happen.

### Inbound-persistent

```python
import asyncio
from siphon_control import ControlClient, ControlError

client = ControlClient(app="ivr-app", token="s3cr3t",
                       url="ws://siphon:9090/control/ws")

@client.on_call
async def handle(call):
    await call.answer()
    try:
        await call.transfer("sip:agent@pbx")   # REFER, awaits correlated reply
    except ControlError as error:
        print("transfer rejected:", error.code)

async def main():
    async with client:          # closes on the way out — see Shutdown below
        await client.run()

asyncio.run(main())
```

### Application-level events

Events an app opts into with `control.apps[].events` (`RegistrationChanged`,
`DialogStateChanged`) concern no call, so they never reach `on_call`. Register a
handler for them; `run()` installs it:

```python
@client.on_app_event
async def on_app_event(event, payload):
    if event == "DialogStateChanged":
        print(payload["aor"], payload["state"])   # early / confirmed / terminated
```

### Per-call-connect

```python
import asyncio
from siphon_control import ControlServer, ControlError

server = ControlServer(app="ivr-app", token="s3cr3t", bind="0.0.0.0:8790")

@server.on_call
async def handle(call):
    await call.answer()
    try:
        await call.transfer("sip:agent@pbx")
    except ControlError as error:
        print("transfer rejected:", error.code)

async def main():
    async with server:
        await server.serve()

asyncio.run(main())
```

## Shutdown

Both classes are async context managers, and `async with` is the recommended
shape. `close()` is the same thing explicitly.

It matters more than it looks. `run()` / `serve()` are driven by a background
tokio task, and every handed-over call is dispatched from another one. Nothing
joins those tasks and the runtime outlives the interpreter, so an app that
finishes without closing leaves them delivering results into an asyncio loop —
and then into a Python — that is no longer there. Closing first means there is
nothing in flight to strand.

Not closing is handled rather than fatal: a handover arriving after the loop or
interpreter has gone is dropped, and a handler cancelled during teardown is not
reported as a failure. That is damage control, not a substitute for closing.

## API

### `ControlClient` (inbound-persistent)

- `ControlClient(app, token, url=…, protocol=1, reply_timeout_ms=…, reconnect_backoff_ms=…)`
- `@client.on_call` — register an async (or sync) per-call handler.
- `await client.connect()` / `await client.run()` — connect / drive (reconnect + resync).
- `await client.command(verb, module=None, target=None, args=None)` — the generic
  `{module, verb, target, args}` primitive for any adapter (SIP today; SMPP/SS7 later).
- `await client.originate(channel, to=None, *, aor=None, strategy=None, total_timeout=None, media=False, sdp=None, body=None, content_type=None, …, session_timer=None)`
  — place an outbound call under a channel id you choose; resolves to
  `{"channel", "call_id", "sip_call_id"}` once the INVITE is on the wire. Exactly one
  media plan (`media=True`, `sdp=` or `body=`). `session_timer={"expires", "min_se",
  "refresher"}` runs an RFC 4028 session timer on the call, each key left out taking the
  server's default. What the server would refuse raises `ValueError` before a frame goes out.
- `await client.describe()` — adapter schema.
- `client.shutdown()` — stop the client and unblock `run()`.
- `client.close()` — shutdown, plus drop the handler so nothing else is
  dispatched. `async with client:` does this on the way out. See Shutdown above.

### `ControlServer` (per-call-connect)

- `ControlServer(app, token, bind="0.0.0.0:8790", reply_timeout_ms=…)` — `bind` is
  the address the app listens on for siphon to dial; the token is validated on the
  incoming upgrade.
- `@server.on_call` — the SAME decorator + `Call` handle as `ControlClient`.
- `await server.bind()` — bind the listener; resolves to the bound address string
  (bind to `…:0` to learn the ephemeral port before siphon dials in).
- `server.local_addr` — the bound address once `bind()` / `serve()` has run, else `None`.
- `await server.serve()` / `await server.run()` — accept siphon's per-call dials
  forever (stop by cancelling the task).
- `server.close()` — drop the handler so no further accepted call is dispatched,
  one accepted while `serve()` is still running included.
  `async with server:` does this on the way out. See Shutdown above.

### `Call` (shared by both modes)

- `Call` verbs: `answer()`, `answer_with(code, …)`, `answer_anchored(profile=None,
  ws_uri=None)`, `ring(reason=None)`, `progress()`, `reject(code, reason)`,
  `hangup(reason=None)`, `refer(to)` / `transfer(to)`, `route(targets, strategy="sequential",
  headers=None)`, `set_header(name, value)`, `get_header(name)`, `remove_header(name)`,
  `set_var(key, value)`, `get_var(key)`, `command(verb, args=None)`, `next_event()`.
- `await call.dial(targets, strategy=None, timeout=None, headers=None, profile=None,
  from_uri=None, from_display=None, p_asserted_identity=None, privacy=None,
  on_answer=None, ringback=None)` rings B-legs
  while the caller stays **unanswered** and this app keeps the channel. Each target
  is a dict: `{"uri": ...}` is dialed as written, `{"aor": ...}` is forked to every
  registered contact over that contact's own captured flow, which is the only way to
  reach a phone registered on TCP, TLS or WSS behind NAT. A bare string is refused,
  because it does not say which of the two was meant.
  With `on_answer="bridge"` it instead rings phones for a caller the app already
  answered and anchored (after a greeting or a menu), plays `ringback` (a tone
  preset or cadence, `True` for the default, `False` for none) while they alert, and
  bridges the first to pick up; the result adds `group_id`, `total_timeout` and the
  `branches` rung.
- `await call.cancel_dial(reason=None)` gives up on the dial that is ringing and
  leaves the caller as the dial found it. Every phone still ringing is CANCELled,
  each reported by `DialBranchFailed` with cause `cancelled`, and the dial ends in
  `DialFailed` with code 487; `reason` is the `cause` of a bridging dial's
  `DialFailed` (default `cancelled`). Raises `ControlError` (`invalid_state`) when
  nothing is ringing, and once a phone has answered and is being bridged.
- `await call.accept_refer(target=None, next_hop=None, mode=None, profile=None, *,
  aor=None, from_uri=None, from_display=None, p_asserted_identity=None, privacy=None,
  headers=None, timeout=None, number_policy=None, format=None)` accepts a pending
  inbound REFER (a `TransferRequested`
  event). `mode` is `"terminate"` (siphon dials the target), `"transparent"` (siphon
  relays the REFER) or `"controller"`: siphon answers `202` and dials nothing, this app
  moves the parties itself and then reports with `await call.complete_refer(code,
  reason=None)`, within `timeout` seconds (default 60, at most 180). `aor=` names the
  target by its registered address-of-record in place of a URI: it is dialled over the
  flow its phone registered on, every registered contact rings and the first to answer
  is kept. The identity arguments are the ones `dial` takes, for the leg the transfer
  dials; `number_policy` names a number policy configured on the server for the
  numbers in them, or `format` gives one format (`"e164"`, `"plain"`,
  `"international"`, `"national"`). A target URI together with `aor=`, `mode="controller"` with any argument that
  describes a leg, and `timeout` with another mode each raise `ValueError` before a
  frame goes out. `await call.reject_refer(code, reason=None)` declines the REFER.
- `await call.replace_peer(target=None, next_hop=None, replace_a_leg=None, profile=None,
  timeout=None, *, aor=None, from_uri=None, from_display=None, p_asserted_identity=None,
  privacy=None, headers=None, number_policy=None, format=None)` swaps one party of
  an answered call for a freshly
  dialled target, with no REFER involved; the replaced leg stays up while the target
  rings. Exactly one of `target` and `aor=` (`ValueError` otherwise). The reply says
  the INVITE is on the wire; `PeerReplaced` / `ReplaceFailed` is the outcome.
- `await call.bridge(with_channel, on_peer_hangup=None)` joins this call to another
  leg the app owns, and `await call.unbridge(reason=None)` parts them, both legs
  staying answered and held. The outcome arrives as `ChannelBridged` / `BridgeFailed`.
- `await call.play(file=None, db_id=None, blob=None, repeat=None, start_ms=None,
  duration_ms=None, to_tag=None, *, tone=None, url=None, gain_decibels=None)` plays an
  announcement on the caller's media. Exactly one source: a `file`, a `db_id`, a
  `blob`, a `tone` (a preset such as `"ringback_eu"` or a cadence) or a `url` (HTTP
  or HTTPS). `repeat` is a total play count, or `"inf"` to play until stopped;
  anything else raises `ValueError`. `gain_decibels` plays louder (positive) or
  quieter (negative). `play_file(file)`, `stop()`, `dtmf(digits, …)`,
  `hold()` and `unhold()` are the other media verbs. `hold` is a media gate, not a
  SIP hold, and is refused (`invalid_state`) on a call the engine only relays.
- `await call.stream_start(ws_uri, direction=None, channels=None, *, mode="tee",
  sample_rate=None, profile=None)` streams the call's audio to a WebSocket server, as
  a copy (`"tee"`) or a takeover (`"bridge"`), and `await call.stream_stop(*,
  mode="tee")` detaches it. siphon-rtp backend only.
- `await client.originate(channel, aor=..., strategy=None, total_timeout=None, …)`
  rings every phone registered at the AoR, each over its own flow and Path; the first
  to answer becomes the channel's call. Exactly one of `to` and `aor`, and
  `strategy` / `total_timeout` only with `aor`. Resolves to `{"channel", "group_id",
  "aor", "strategy", "total_timeout", "branches"}`.
- `await call.record_start(direction=None, channels=None, max_duration_ms=None,
  silence_ms=None, path=None)` records the call's decoded audio to a wav file and
  returns the `recording_id` that `await call.record_stop(recording_id=None)`
  addresses (no id stops every recording on the call). The reply is the accept;
  the `RecordingFinished` event says the file is closed. siphon-rtp backend only.
- `await call.drop(reason=None, *, ban=False)` abandons an **unanswered** call with nothing on
  the wire — no final response, no CANCEL — and releases it. Use it for traffic
  addressed to nothing your controller serves: a `404` confirms the number to an
  enumeration sweep, silence does not. An answered call raises `ControlError` with
  `code == "invalid_state"` (its dialog is owed a BYE — that is `hangup`); the
  reason reaches siphon's log and the CDR, not the peer. `ban=True` also scores the
  caller's source toward an auto-ban (`security.failed_auth_ban`), so a source the
  controller keeps dropping is refused at the transport.
- `unsupported_verb` is what a verb raises when the configured media backend cannot
  carry it out: the stream and record verbs on rtpengine or rtpproxy, and
  `play(repeat="inf")` there.

## Errors

A rejected command raises `ControlError` carrying a stable `.code`
(`not_found`, `forbidden`, `unsupported_verb`, `unauthorized`, …).

## Build

```
maturin develop        # into the active venv
maturin build --release
```

The target interpreter is free-threaded CPython 3.14t (the SIPhon runtime); the
wheel also loads on a standard GIL build.

## License

MIT
