# SIPhon control-plane SDKs

Client SDKs for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class rail for driving
handed-over B2BUA calls out of process.

**These SDKs are the supported way to build a SIPhon controller.** They hide the
wire — no hand-rolled JSON, no request-id bookkeeping, no reconnect loop — and
version against the `siphon-control.v1` protocol independently of the siphon
server, so a controller you write today keeps working across siphon upgrades.
Build against the [raw protocol](#the-raw-protocol) only when you need a client
in a language the SDKs don't cover.

## Install

| Language | Install | Crate / package |
| --- | --- | --- |
| Python | `pip install siphon-control` | `siphon-control` (PyPI) |
| Rust | `cargo add siphon-control-client` | `siphon-control-client` (crates.io) |

```python
import asyncio
from siphon_control import ControlClient, ControlError

client = ControlClient(app="ivr-app", token="s3cr3t",
                       url="ws://siphon:9090/control/ws")

@client.on_call
async def handle(call):
    await call.answer()
    try:
        await call.transfer("sip:agent@pbx")
    except ControlError as error:
        print("transfer rejected:", error.code)

asyncio.run(client.run())
```

## The crates

| Crate | Publishes to | Role |
| --- | --- | --- |
| [`siphon-control-proto`](siphon-control-proto/) | crates.io | Dependency-light wire DTOs (`CommandFrame` / `ReplyFrame` / `EventFrame`, error codes, handshake) — the single source of truth for the frames, shared by the server and every SDK. |
| [`siphon-control-client`](siphon-control-client/) | crates.io | Async Rust client: protocol-agnostic core (`command(module, verb, target, args)`, request-id correlation, reconnect + `resync`) plus a typed `sip::Call` facade. |
| [`siphon-control`](siphon-control/) | PyPI (wheel) | PyO3 bindings over the Rust client — `ControlClient` + `Call` as asyncio awaitables, `@client.on_call` dispatch. |

`siphon-control` is a **native** extension, not pure Python. There is no abi3
for free-threaded CPython, so wheels are built per interpreter: **cp314 (GIL)
and cp314t (free-threaded)** ship as separate wheels, since the SIPhon runtime
is free-threaded.

## Versioning & release

The three crates share one version (`0.1.0`), independent of the siphon server
and tied to the `siphon-control.v1` protocol. They release on their own tag
train — `control-sdk-vX.Y.Z` — driving
[`.github/workflows/release-control-sdk.yaml`](../.github/workflows/release-control-sdk.yaml),
which builds the wheels (maturin) and publishes to PyPI and crates.io via OIDC
Trusted Publishing (no stored tokens). This is a **standalone excluded
workspace** with its own `Cargo.lock`: a root `cargo build` of siphon-sip never
sweeps it, and nothing here publishes on its own — only a `control-sdk-v*` tag
does.

## The raw protocol

The SDKs speak `siphon-control.v1`: one WebSocket per connection, request-id
correlated JSON text frames. The complete wire reference, both connection modes,
and two low-level example clients (Python + TypeScript) that drive calls with no
SDK live under
[`examples/remote_control/`](../examples/remote_control/). Reach for that layer
only to build a client in a language the SDKs don't cover.

Full documentation: <https://siphon-sip.org/reference/control-plane/>

## License

MIT
