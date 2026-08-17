/**
 * Example external control application for the siphon control plane — TypeScript SDK.
 *
 * Drives live B2BUA calls a script hands over with `call.handover("ivr-app")` (the
 * ARI *Stasis* model) over siphon's control WebSocket, using the `@siphon-project/control`
 * SDK. The SDK owns the wire completely: no `ws`, no manual JSON, no request-id
 * bookkeeping — you get a `Call` whose verbs read like an in-process siphon script
 * (`call.answer()` / `call.transfer(...)` / `call.hangup()`).
 *
 * Two connection modes, same wire (subprotocol `siphon-control.v1`):
 *
 *   - **outbound per-call-connect (the default)** — this app is a WebSocket
 *     *server* (`SipServer`); siphon dials it once per handed-over call and the
 *     accepting socket owns that call. No `hello` — the first frame is
 *     `StasisStart`. Use this for multi-pod / autoscaled controllers (siphon
 *     always dials *out*, so the "which pod owns the call" affinity problem
 *     cannot arise).
 *   - **inbound persistent** — this app is a WebSocket *client* (`SipClient`)
 *     that connects in to `control.listen` and owns calls assigned to it. It
 *     sends a `hello` and `resync`s to re-attach its calls after a reconnect.
 *
 * `SipClient` / `SipServer` are the SIP facade over the generic `ControlClient` /
 * `ControlServer` core; both expose the same `onCall(handler)` + `Call` verbs.
 *
 * Select the mode with `SIPHON_CONTROL_MODE` (`outbound` | `inbound`).
 *
 * Install the SDK:
 *   npm i @siphon-project/control            # once published
 *   # this example already depends on it via a file: path to the sibling package,
 *   # so `npm install` here wires it up (build the SDK first — see README.md).
 *
 * Usage:
 *   npm install
 *   # outbound (default): siphon dials this server
 *   SIPHON_CONTROL_BIND=0.0.0.0:8443 IVR_APP_TOKEN=changeme-dev-token npm start
 *   # inbound: this app dials siphon
 *   SIPHON_CONTROL_MODE=inbound IVR_APP_TOKEN=changeme-dev-token npm start
 *
 * See README.md for the matching siphon `control:` config and handover script.
 */
import { SipClient, SipServer, ControlError } from "@siphon-project/control";
import type { Call } from "@siphon-project/control";

const MODE = (process.env.SIPHON_CONTROL_MODE ?? "outbound").toLowerCase();
const APP_NAME = process.env.SIPHON_CONTROL_APP ?? "ivr-app";
const TOKEN = process.env.IVR_APP_TOKEN ?? "changeme-dev-token";
const CONTROL_URL = process.env.SIPHON_CONTROL_URL ?? "ws://127.0.0.1:9092/control/ws";
const BIND = process.env.SIPHON_CONTROL_BIND ?? "127.0.0.1:8443";
const ANSWER_HOLD_MS = 5000;

/** The demo call flow: answer, stamp a per-call variable, hold, then hang up. */
async function handleCall(call: Call): Promise<void> {
  console.log(`[call] StasisStart ${call.channelId} sip_call_id=${call.sipCallId}`);
  try {
    await call.answer();
    // Per-call variables live on the control channel (drain with the call).
    await call.setVar("demo", "1");
    const demo = await call.getVar("demo");
    console.log(`[call] answered ${call.channelId}; demo=${demo}; holding ${ANSWER_HOLD_MS}ms`);
    await new Promise((resolve) => setTimeout(resolve, ANSWER_HOLD_MS));
    // Blind transfer instead of hanging up? -> await call.transfer("sip:agent@pbx")
    await call.hangup(); // alias for call.terminate()
    console.log(`[call] hung up ${call.channelId}`);
  } catch (error) {
    if (error instanceof ControlError) {
      // A dead/unknown call is a typed `not_found`; a verb the server does not
      // implement yet is `unsupported_verb`. Never fatal to the other calls.
      console.log(`[call] ${call.channelId} rejected: ${error.code}`);
    } else {
      throw error;
    }
  }
}

/** Inbound persistent: dial siphon, hello, resync, then drive assigned calls. */
async function runInbound(): Promise<void> {
  const client = await SipClient.connect({ url: CONTROL_URL, app: APP_NAME, token: TOKEN });
  console.log(`[control] connected (inbound) to ${CONTROL_URL} as ${APP_NAME}`);
  await client.onCall(handleCall); // drives reconnect + resync to completion
}

/** Outbound per-call-connect: siphon dials this server once per handed-over call. */
async function runOutbound(): Promise<void> {
  const [host, port] = BIND.split(":");
  const server = await SipServer.bind({
    host: host ?? "127.0.0.1",
    port: Number(port ?? 8443),
    app: APP_NAME,
    token: TOKEN,
  });
  console.log(`[control] listening (outbound per-call-connect) on ws://${BIND}`);
  await server.onCall(handleCall);
}

async function main(): Promise<void> {
  if (MODE === "inbound") {
    await runInbound();
  } else if (MODE === "outbound") {
    await runOutbound();
  } else {
    throw new Error(`SIPHON_CONTROL_MODE must be 'outbound' or 'inbound' (got ${MODE})`);
  }
}

main().catch((error: unknown) => {
  console.error(error);
  process.exitCode = 1;
});
