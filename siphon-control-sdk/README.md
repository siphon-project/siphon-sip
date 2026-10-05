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
| TypeScript | `npm install @siphon-project/control ws` | `@siphon-project/control` (npm) |

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

## What a controller can do

All three SDKs wrap every verb the server's `sip` adapter describes; each
package's README lists them under its own names.

- **Answer, or not:** `answer`, an anchored answer on the media engine, `ring`,
  `progress`, `reject`, `hangup`, and `drop` for an unanswered call that is owed
  no response.
- **Place and ring calls:** `originate` to a URI or to a registered AoR; `dial`
  to ring B-legs while keeping the channel, or with `on_answer: "bridge"` to ring
  phones for an answered caller; `cancel_dial` to give a ringing dial up and
  keep the caller; `route` to hand the call back to siphon.
- **Transfer:** `refer`; `accept_refer` / `reject_refer` for an inbound REFER,
  carried out by siphon (`terminate`), relayed (`transparent`) or left to the
  application (`controller`, then `complete_refer` to report how it went);
  `replace_peer` to swap a party with no REFER involved. A transfer target is a
  URI or `{aor}`, a registered address-of-record, and the leg the transfer dials
  takes the identity arguments `dial` takes (`from`, `from_display`,
  `p_asserted_identity`, `privacy`, `headers`).
- **Join calls:** `bridge` and `unbridge`.
- **Media:** `play` (`repeat` is a total play count, or `"inf"` to play until
  stopped), `stop`, `dtmf`, `hold` / `unhold`, `stream_start` / `stream_stop`,
  `record_start` / `record_stop`.
- **Headers and variables:** `set_header` / `get_header` / `remove_header`,
  `set_var` / `get_var`.

A verb the configured media backend cannot carry out answers `unsupported_verb`:
streaming, recording and an endless `play` need the siphon-rtp backend.

## The crates

| Crate | Publishes to | Role |
| --- | --- | --- |
| [`siphon-control-proto`](siphon-control-proto/) | crates.io | Dependency-light wire DTOs (`CommandFrame` / `ReplyFrame` / `EventFrame`, error codes, handshake) — the single source of truth for the frames, shared by the server and every SDK. |
| [`siphon-control-client`](siphon-control-client/) | crates.io | Async Rust client: protocol-agnostic core (`command(module, verb, target, args)`, request-id correlation, reconnect + `resync`) plus a typed `sip::Call` facade. |
| [`siphon-control`](siphon-control/) | PyPI (wheel) | PyO3 bindings over the Rust client — `ControlClient` + `Call` as asyncio awaitables, `@client.on_call` dispatch. |
| [`@siphon-project/control`](typescript/) | npm | TypeScript / Node client over the same wire: `SipClient` / `SipServer` and a typed `Call`. Not a crate, and not built on the Rust client. |

`siphon-control` is a **native** extension, not pure Python. There is no abi3
for free-threaded CPython, so wheels are built per interpreter: **cp314 (GIL)
and cp314t (free-threaded)** ship as separate wheels, since the SIPhon runtime
is free-threaded.

## Versioning & release

The three crates and the TypeScript package share one version, independent of
the siphon server and tied to the `siphon-control.v1` protocol. They release on
their own tag train — `control-sdk-vX.Y.Z` — driving
[`.github/workflows/release-control-sdk.yaml`](../.github/workflows/release-control-sdk.yaml),
which builds the wheels (maturin) and publishes to PyPI and crates.io, and
[`.github/workflows/release-control-sdk-ts.yaml`](../.github/workflows/release-control-sdk-ts.yaml),
which publishes to npm, all via OIDC Trusted Publishing (no stored tokens). This is a **standalone excluded
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
