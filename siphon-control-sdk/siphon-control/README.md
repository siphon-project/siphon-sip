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
- `server.close()` — drop the handler so no further accepted call is dispatched.
  `async with server:` does this on the way out. See Shutdown above.

### `Call` (shared by both modes)

- `Call` verbs: `answer()`, `answer_with(code, …)`, `progress()`, `reject(code, reason)`,
  `hangup(reason=None)`, `refer(to)` / `transfer(to)`, `set_header(name, value)`,
  `get_header(name)`, `set_var(key, value)`, `get_var(key)`, `command(verb, args=None)`,
  `next_event()`.
- Media verbs `play_file(file)` / `dtmf(digits)` raise `ControlError` with
  `code == "unsupported_verb"` until the server implements media.

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
