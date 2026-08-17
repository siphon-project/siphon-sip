# @siphon/control (TypeScript)

TypeScript / Node client for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class rail for driving
handed-over calls out of process. The third client language alongside the Rust
(`siphon-control-client`) and Python (`siphon-control`) SDKs, over the
byte-identical wire.

The wire is hidden: no manual JSON, no request-id bookkeeping, no hand-rolled
`rpc()`. You get a `Call` handle whose verbs mirror the in-process siphon
scripting API (`call.answer()`, `call.terminate()`, `call.transfer()`, …), so an
out-of-process controller reads like an in-process script.

> **Package name.** Published as the scoped `@siphon/control`. If the `@siphon`
> npm organization is unavailable at publish time, the fallback is the unscoped
> `siphon-control` — the import surface is identical either way.

## Install

```sh
npm install @siphon/control ws
```

`ws` is a peer runtime dependency (the Node WebSocket implementation).

## Quick start

```ts
import { SipClient, ControlError } from "@siphon/control";

const client = await SipClient.connect({
  url: "ws://siphon:9090/control/ws",
  app: "ivr-app",
  token: "s3cr3t",
});

await client.onCall(async (call) => {
  await call.answer();
  try {
    await call.transfer("sip:agent@pbx"); // REFER; awaits the correlated reply
  } catch (error) {
    if (error instanceof ControlError) {
      console.log("transfer rejected:", error.code);
    }
  }
});
```

## Two connection modes

Same wire protocol (subprotocol `siphon-control.v1`), two ways to connect:

- **Inbound-persistent** (`SipClient`): the app is a WebSocket *client* that
  dials into siphon's `control.listen`, sends a `hello`, and owns the calls
  assigned to it. It can `resync` to re-attach its calls after a reconnect.
- **Per-call-connect** (`SipServer`, the documented multi-pod default): siphon
  *dials the app* once per handed-over call, so the app is a WebSocket *server*.
  No `hello` — the first frame is `StasisStart`, and the accepting socket owns
  exactly that one call, so "the audio lands on the wrong pod" is structurally
  impossible.

```ts
import { SipServer } from "@siphon/control";

const server = await SipServer.bind({
  host: "0.0.0.0",
  port: 8443,
  app: "ivr-app",
  token: "changeme-dev-token",
});
await server.onCall(async (call) => {
  await call.answer();
});
```

## Layering: protocol-agnostic core + typed facade

- `ControlClient` / `ControlServer` are the **generic core**: transport, `hello`,
  request-id correlation, reconnect + `resync`, and a generic event stream.
  Their headline primitive is `command(module, verb, target, args)`, which works
  for any adapter (`sip` today; `smpp`/`ss7` later) with zero changes.
- `SipClient` / `SipServer` are the **typed SIP facade** on top: a `Call`'s
  verbs are thin wrappers over `command("sip", …)`, and `StasisStart`→`Call`
  dispatch lives there. A future `smpp` / `ss7` facade is an additive sibling
  over the same core.

```ts
// The generic escape hatch (any module / verb):
const schema = await client.controlClient.describe();
await client.command("sip", "answer", { channel: "ch1" }, { code: 200 });
```

## `Call` verbs (mirror the in-process scripting API)

| Method | Wire verb (`module`) | Notes |
| --- | --- | --- |
| `answer(options?)` | `answer` (`sip`) | UAS 2xx (default `200 OK`) |
| `progress(options?)` | `progress` (`sip`) | UAS 1xx / early media (default `183`) |
| `reject(code, reason?)` | `reject` (`sip`) | final non-2xx + teardown |
| `terminate(reason?)` | `hangup` (`sip`) | primary teardown name |
| `hangup(reason?)` | `hangup` (`sip`) | alias for `terminate` |
| `refer(to)` | `refer` (`sip`) | in-dialog REFER (blind transfer) |
| `transfer(to)` | `refer` (`sip`) | alias for `refer` |
| `referReplaces(to, replaces)` | `refer` (`sip`) | attended transfer (RFC 3891) |
| `setHeader(name, value)` | `set_header` (`sip`) | on the stored A-leg INVITE |
| `getHeader(name)` | `get_header` (`sip`) | returns `string \| null` |
| `setVar(key, value)` | `set_var` (substrate) | per-call variable |
| `getVar(key)` | `get_var` (substrate) | returns `string \| null` |
| `removeHeader(name)` | `remove_header` (`sip`) | ‡ |
| `acceptRefer(options?)` | `accept_refer` (`sip`) | ‡ |
| `rejectRefer(code, reason?)` | `reject_refer` (`sip`) | ‡ |
| `playFile(file)` | `play` (`sip`) | ‡ media |
| `dtmf(digits)` | `dtmf` (`sip`) | ‡ media |
| `command(verb, args?)` | (`sip`) | arbitrary SIP-adapter verb |
| `nextEvent()` / `events()` | — | per-call event stream |

Identity/context getters: `channelId`, `callId`, `sipCallId`, `app`, `payload`,
`reattached`.

‡ Accepted verb names the Phase-1 server answers with a `ControlError` whose
`.code === "unsupported_verb"` (`error.isUnsupportedVerb()`) until it implements
them. They send a real command — nothing is stubbed client-side.

## Errors

A `status:"error"` reply throws a `ControlError` carrying the stable wire code in
`.code` (`not_found`, `forbidden`, `unsupported_verb`, `unauthorized`, …).
Transport / handshake / timeout failures throw a `ControlError` with a `.kind`
(`unauthorized`, `handshake`, `closed`, `timeout`, `websocket`, `config`) and no
`.code`.

```ts
try {
  await call.playFile("/prompts/welcome.wav");
} catch (error) {
  if (error instanceof ControlError && error.isUnsupportedVerb()) {
    // media isn't wired server-side yet — fall back gracefully
  }
}
```

## Build & test

```sh
npm install
npm run build      # dual ESM + CJS + .d.ts (tsup)
npm run typecheck  # tsc --noEmit
npm test           # vitest
```

The package ships ESM and CommonJS with type declarations for both. The
`wire.test.ts` suite pins the exact command bytes against the server contract.

## License

MIT
