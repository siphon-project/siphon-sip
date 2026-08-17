# siphon-control (Python)

Python client for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class rail for driving
handed-over calls out of process. Built with [PyO3](https://pyo3.rs) over the
async Rust client, so the wire is hidden: no manual JSON, no request-id
bookkeeping.

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

asyncio.run(client.run())
```

## API

- `ControlClient(app, token, url=…, protocol=1, reply_timeout_ms=…, reconnect_backoff_ms=…)`
- `@client.on_call` — register an async (or sync) per-call handler.
- `await client.connect()` / `await client.run()` — connect / drive (reconnect + resync).
- `await client.command(verb, module=None, target=None, args=None)` — the generic
  `{module, verb, target, args}` primitive for any adapter (SIP today; SMPP/SS7 later).
- `await client.describe()` — adapter schema.
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
