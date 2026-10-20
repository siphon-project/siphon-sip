# @siphon-project/control (TypeScript)

TypeScript / Node client for the [SIPhon](https://github.com/siphon-project/siphon-sip)
external control plane (`siphon-control.v1`) — an ARI/ESL-class rail for driving
handed-over calls out of process. The third client language alongside the Rust
(`siphon-control-client`) and Python (`siphon-control`) SDKs, over the
byte-identical wire.

The wire is hidden: no manual JSON, no request-id bookkeeping, no hand-rolled
`rpc()`. You get a `Call` handle whose verbs mirror the in-process siphon
scripting API (`call.answer()`, `call.terminate()`, `call.transfer()`, …), so an
out-of-process controller reads like an in-process script.

> **Package name.** Published as `@siphon-project/control` (scoped to the
> `siphon-project` npm org).

## Install

```sh
npm install @siphon-project/control ws
```

`ws` is a peer runtime dependency (the Node WebSocket implementation).

## Quick start

```ts
import { SipClient, ControlError } from "@siphon-project/control";

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
import { SipServer } from "@siphon-project/control";

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
| `answer(options?)` | `answer` (`sip`) | UAS 2xx (default `200 OK`). `options.contactHost` (here, on `answerAnchored`, `ring` and `progress`) is the host of siphon's own Contact toward the caller, for a peer that identifies the tenant by it; fixed once an 18x or 2xx went out (another is `invalid_state`) |
| `answerAnchored(options?)` | `answer` (`sip`) | answer and anchor the caller's media on the media engine in one act (`profile`, `wsUri`); what `play`, `hold` and `dial` with `onAnswer: "bridge"` need |
| `ring(reason?, options?)` | `ring` (`sip`) | `180 Ringing`: alerting only, no early media |
| `progress(options?)` | `progress` (`sip`) | UAS 1xx / early media (default `183`) |
| `reject(code, reason?)` | `reject` (`sip`) | final non-2xx + teardown |
| `terminate(reason?)` | `hangup` (`sip`) | primary teardown name |
| `hangup(reason?)` | `hangup` (`sip`) | alias for `terminate` |
| `drop(reason?, options?)` | `drop` (`sip`) | abandon an **unanswered** call with nothing on the wire — no final response, no CANCEL. Refused on an answered call, whose dialog is owed a BYE; the reason goes to the log and the CDR. `{ ban: true }` also scores the caller's source toward `security.failed_auth_ban` (strong over TCP/TLS/WS/WSS, weight 1 over UDP; a no-op without the ban store) |
| `refer(to)` | `refer` (`sip`) | in-dialog REFER (blind transfer) |
| `transfer(to)` | `refer` (`sip`) | alias for `refer` |
| `referReplaces(to, replaces)` | `refer` (`sip`) | attended transfer (RFC 3891) |
| `setHeader(name, value)` | `set_header` (`sip`) | on the stored A-leg INVITE |
| `getHeader(name)` | `get_header` (`sip`) | returns `string \| null` |
| `setVar(key, value)` | `set_var` (substrate) | per-call variable |
| `getVar(key)` | `get_var` (substrate) | returns `string \| null` |
| `removeHeader(name)` | `remove_header` (`sip`) | on the stored A-leg INVITE |
| `route(targets, strategy?, headers?, options?)` | `route` (`sip`) | hand the call back to siphon with a routing decision: the targets are tried in order. A target's `route` is the route set its INVITE carries, topmost first, and its `contactHost` the host of siphon's own Contact on that attempt. `options.callerContactHost` is the host of siphon's Contact toward the caller, as `contactHost` is on `answer`. Refused `invalid_state` while a `dial` still rings; `cancelDial` first |
| `acceptRefer(options?)` | `accept_refer` (`sip`) | accept a pending inbound REFER (a `TransferRequested` event). `mode` is `"terminate"` (siphon dials the target), `"transparent"` (siphon relays the REFER) or `"controller"` (siphon answers `202` and dials nothing; this app moves the parties and reports with `completeRefer` within `timeout` seconds, default 60, at most 180). `target` is a URI string or `{ aor }`, a registered address-of-record dialled over the flow its phone registered on, every registered contact rung and the first to answer kept. `from`, `fromDisplay`, `pAssertedIdentity`, `privacy` and `headers` shape the leg the transfer dials, and `numberPolicy` (a number policy configured on the server) or `format` says how the numbers in them are written. `{ aor }` and the identity options go with `"terminate"`; `"controller"` takes `timeout` only, and `timeout` goes with no other mode. The server refuses the rest |
| `rejectRefer(code, reason?)` | `reject_refer` (`sip`) | decline a pending inbound REFER with a final non-2xx |
| `completeRefer(code, reason?)` | `complete_refer` (`sip`) | report how a transfer accepted with `acceptRefer({ mode: "controller" })` went: the referrer gets the sipfrag NOTIFY that ends its subscription, a 2xx for success. Report before releasing the referrer's leg |
| `bridge(withChannel, options?)` | `bridge` (`sip`) | join two answered legs; the verdict arrives as `ChannelBridged` / `BridgeFailed` |
| `unbridge(reason?)` | `unbridge` (`sip`) | break the bridge — both legs stay answered, owned and held |
| `dial(targets, options?)` | `dial` (`sip`) | ring B-legs while the caller stays **unanswered** and this app keeps the channel. A target is `{uri}` (dialed as written) or `{aor}` (forked to every registered contact over its own flow); one naming both, or neither, throws. A `{uri}` target may carry `route`, the route set its INVITE carries, topmost first (`["<sip:term@scscf.example;lr;odi=4f1c>"]`), which is how an IMS application server sends a session back through the S-CSCF; a `route` on `{aor}` throws. Either form may carry `contactHost`, the host siphon presents in its own Contact on that leg in place of the address it advertises, for a peer that identifies the tenant or account by that host (only the host changes). Either form may carry `profile`, the media profile for that branch alone over the dial's own; a target without one inherits the dial's (a connecting dial that names no `profile` anchors every branch or none, so either every target names one or none does). Either form may carry `rerouteAfterProgress` (a boolean, anything else throws; server default `true`): `false` ends a sequential dial on that target once it has rung, its ring timeout, busy or other failure being the dial's, for a hunt across several routes to one destination; a target that never rang, and a 503 with Retry-After, still move the hunt on, and a 6xx ends a sequential dial either way. `callerContactHost` in the options is the caller's side: the host of siphon's Contact toward the caller (on a bridging dial it can only repeat the one the caller's answer carried). `onAnswer: "bridge"` rings phones for an **answered**, anchored caller and bridges the first to pick up, with `ringback` playing meanwhile; `ringback` without it throws. `offer: "early"` (in the options, or on a target, which wins) sends each phone of a bridge dial an SDP offer in its INVITE, allocated on the media engine from the caller's media, for peers that refuse a delayed-offer INVITE; `"delayed"` is the server's default, and `offer` without `onAnswer: "bridge"` throws |
| `cancelDial(reason?)` | `cancel_dial` (`sip`) | give up on the dial ringing for this call and leave the caller alone: the phones are CANCELled, each reported by `DialBranchFailed` (cause `cancelled`), and the dial ends in `DialFailed` with code 487. `reason` is the `cause` of a bridging dial's `DialFailed` (default `cancelled`). Refused `invalid_state` when nothing is ringing, and once a phone has answered and is being bridged |
| `replacePeer(target, options?)` | `replace_peer` (`sip`) | swap one party of this answered call for a freshly dialled target, no REFER involved; the replaced leg stays up while the target rings. `target` is a URI string or `{ aor }`, and `options` takes `nextHop`, `replaceALeg`, `profile`, `timeout` and the identity options of `acceptRefer`. The verdict arrives as `PeerReplaced` / `ReplaceFailed` |
| `recordStart(options?)` | `record_start` (`sip`) | record the call's decoded audio to a wav file; the reply names the `recordingId`, `RecordingFinished` says the file is closed. siphon-rtp only |
| `recordStop(recordingId?)` | `record_stop` (`sip`) | stop one recording, or every recording on the call when no id is given |
| `play(source, options?)` | `play` (`sip`) | play `{ file }`, `{ dbId }`, `{ blob }`, `{ tone }` (a preset or a cadence) or `{ url }` (HTTP or HTTPS) on the caller's media. `options.repeat` is a total play count, or `"inf"` to play until stopped (`stop` ends it); also `startMs`, `durationMs`, `gainDecibels`, `toTag`. Needs an anchored media session (`not_found` without one) |
| `playFile(file)` | `play` (`sip`) | `play({ file })` with default options |
| `stop()` | `stop` (`sip`) | stop the announcement that is playing |
| `dtmf(digits, options?)` | `dtmf` (`sip`) | inject DTMF digits toward the caller (`durationMs`, `volumeDbm0`, `pauseMs`, `toTag`) |
| `hold()` / `unhold()` | `hold` / `unhold` (`sip`) | silence, then restore, the call's media on the engine. A media gate, not a SIP hold; refused `invalid_state` on a call the engine only relays |
| `streamStart(wsUri, options?)` | `stream_start` (`sip`) | stream the call's audio to a WebSocket server: `mode: "tee"` (default, a copy) or `"bridge"` (a takeover). siphon-rtp only |
| `streamStop(options?)` | `stream_stop` (`sip`) | detach the stream of `options.mode` |
| `command(verb, args?)` | (`sip`) | arbitrary SIP-adapter verb |
| `nextEvent()` / `events()` | — | per-call event stream |

Identity/context getters: `channelId`, `callId`, `sipCallId`, `app`, `payload`,
`reattached`.

Placing a call lives on `SipClient`, since it creates a channel rather than
addressing one:

| Method | Wire verb (`module`) | Notes |
| --- | --- | --- |
| `originate(channel, to, media, options?)` | `originate` (`sip`) | one URI, resolved as written; resolves once the INVITE is on the wire to the `Call` it placed, whose `nextEvent()` carries the answer, a rejection or the ring timeout. An id still live on this client is `conflict`, refused before anything is sent. `options.contactHost` presents that host in siphon's own Contact on the call (on every leg of `originateAor`) |
| `originateAor(channel, aor, media, options?, ring?)` | `originate` (`sip`) | ring every phone registered at `aor` over its own flow and Path; first to answer wins. `ring` is `{ strategy?, totalTimeout? }`. The result carries the placed `call`. Nobody registered is `not_found` (`no_contacts`); `drop` is refused while the phones ring, use `hangup` |

The server implements every verb in these tables. `unsupported_verb`
(`error.isUnsupportedVerb()`) is what a verb answers when the configured media
backend cannot carry it out: `streamStart` / `streamStop` and `recordStart` /
`recordStop` on rtpengine or rtpproxy, and `play` with `repeat: "inf"` there.

## Errors

A `status:"error"` reply throws a `ControlError` carrying the stable wire code in
`.code` (`not_found`, `forbidden`, `unsupported_verb`, `unauthorized`, …).
Transport / handshake / timeout failures throw a `ControlError` with a `.kind`
(`unauthorized`, `handshake`, `closed`, `timeout`, `websocket`, `config`) and no
`.code`.

```ts
try {
  await call.streamStart("wss://transcriber.example.com/stream");
} catch (error) {
  if (error instanceof ControlError && error.isUnsupportedVerb()) {
    // the configured media backend cannot stream — carry on without it
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
