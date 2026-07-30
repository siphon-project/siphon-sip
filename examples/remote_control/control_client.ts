/**
 * Example external control application for the siphon control plane.
 *
 * Drives live B2BUA calls a script hands over with `call.handover("<app>")` (the
 * ARI *Stasis* model) over siphon's control WebSocket. Calls that are not handed
 * over are unaffected.
 *
 * Two connection modes, same wire protocol (subprotocol `siphon-control.v1`):
 *
 *   - **outbound per-call-connect (the default)** — this app runs a WebSocket
 *     *server*; siphon dials it once per handed-over call and the accepting
 *     socket owns that call. No `hello` — the first frame is `StasisStart`. Use
 *     this for multi-pod / autoscaled controllers (siphon always dials *out*, so
 *     the "which pod owns the call" affinity problem cannot arise).
 *   - **inbound persistent** — this app is a WebSocket *client* that connects in
 *     to `control.listen` and owns calls assigned to it (round-robin). It sends a
 *     `hello` and can `resync` to re-attach its calls after a reconnect.
 *
 * Select the mode with `SIPHON_CONTROL_MODE` (`outbound` | `inbound`).
 *
 * The Phase-1 verb set is `answer` / `progress` / `reject` / `hangup` / `refer` /
 * `set_header` / `get_header` (SIP adapter, `module: "sip"`) plus the substrate
 * verbs `resync` / `describe` / `set_var` / `get_var`.
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
import WebSocket, { WebSocketServer } from "ws";

const SUBPROTOCOL = "siphon-control.v1";

const MODE = (process.env.SIPHON_CONTROL_MODE ?? "outbound").toLowerCase();
const APP_NAME = process.env.SIPHON_CONTROL_APP ?? "ivr-app";
const TOKEN = process.env.IVR_APP_TOKEN ?? "changeme-dev-token";
const CONTROL_URL = process.env.SIPHON_CONTROL_URL ?? "ws://127.0.0.1:9092/control/ws";
const BIND = process.env.SIPHON_CONTROL_BIND ?? "127.0.0.1:8443";
const ANSWER_HOLD_MS = 5000;

// Verbs the SIP adapter serves (routed with module="sip"); everything else is a
// substrate verb (hello/resync/describe/set_var/get_var) and omits the module.
const SIP_VERBS = new Set([
  "answer", "progress", "reject", "hangup", "refer", "set_header", "get_header",
]);

interface ReplyFrame {
  id: string;
  type: "reply";
  status: "ok" | "error";
  result?: any;
  error?: { code: string; message: string };
}

interface EventFrame {
  type: "event";
  event: string;
  channel?: string;
  call_id?: string;
  sip_call_id?: string;
  payload?: any;
}

type InboundFrame = ReplyFrame | EventFrame;

/** One control connection with request/reply correlation + event dispatch. */
class ControlSession {
  private nextId = 1;
  private readonly pending = new Map<string, (reply: ReplyFrame) => void>();

  constructor(private readonly socket: WebSocket) {
    socket.on("message", (data) => this.onMessage(data.toString()));
  }

  /** Send a command and resolve with its correlated reply frame. */
  rpc(verb: string, target: unknown = {}, args: unknown = {}): Promise<ReplyFrame> {
    const id = `c-${this.nextId++}`;
    const command: Record<string, unknown> = { id, type: "command", verb, target, args };
    if (SIP_VERBS.has(verb)) command.module = "sip";
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.socket.send(JSON.stringify(command));
    });
  }

  private onMessage(raw: string): void {
    const frame = JSON.parse(raw) as InboundFrame;
    if (frame.type === "reply") {
      const resolve = this.pending.get(frame.id);
      if (resolve) {
        this.pending.delete(frame.id);
        resolve(frame);
      }
    } else if (frame.type === "event") {
      // Handle each event concurrently so a long call flow never blocks the read
      // loop (and thus never stalls another call).
      void this.onEvent(frame);
    }
  }

  private async onEvent(event: EventFrame): Promise<void> {
    if (event.event === "StasisStart" && event.channel) {
      console.log(`[event] StasisStart ${event.channel} sip_call_id=${event.sip_call_id}`);
      await this.handleCall(event.channel);
    } else if (event.event === "StasisEnd") {
      console.log(`[event] StasisEnd ${event.channel} reason=${event.payload?.reason}`);
    } else {
      console.log(`[event] ${event.event} ${event.channel ?? ""}`);
    }
  }

  async handleCall(channel: string): Promise<void> {
    const target = { channel };
    const answered = await this.rpc("answer", target, { code: 200 });
    if (answered.status !== "ok") {
      console.log("[call] answer rejected:", answered.error);
      return;
    }
    // Per-call variables live on the control channel (drain with the call).
    await this.rpc("set_var", target, { key: "demo", value: "1" });
    const got = await this.rpc("get_var", target, { key: "demo" });
    console.log(`[call] answered ${channel}; demo=${got.result?.value}; holding ${ANSWER_HOLD_MS}ms`);
    await new Promise((resolve) => setTimeout(resolve, ANSWER_HOLD_MS));
    const hung = await this.rpc("hangup", target);
    console.log(`[call] hangup ${channel}: ${hung.status}`);
  }

  /** Register this connection (inbound mode hello handshake) + resync. */
  async register(): Promise<void> {
    const hello = await this.rpc("hello", {}, { app: APP_NAME, protocol: 1 });
    if (hello.status !== "ok") {
      throw new Error(`hello rejected: ${JSON.stringify(hello.error)}`);
    }
    console.log(`[control] registered as ${APP_NAME}`);
    const resync = await this.rpc("resync");
    const owned = (resync.result?.channels ?? []) as Array<{ channel: string }>;
    console.log(`[control] resync re-attached ${owned.length} call(s)`);
    for (const call of owned) void this.handleCall(call.channel);
  }
}

/** Client mode: dial siphon, hello, resync, then drive assigned calls. */
function runInbound(): void {
  const socket = new WebSocket(CONTROL_URL, [SUBPROTOCOL], {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const session = new ControlSession(socket);
  socket.on("open", () => {
    console.log(`[control] connected (inbound) to ${CONTROL_URL}`);
    session.register().catch((error) => {
      console.error(error);
      socket.close();
    });
  });
  socket.on("error", (error) => console.error("[control] socket error:", error));
  socket.on("close", () => console.log("[control] connection closed"));
}

/** Server mode: siphon dials us per call — we already own it (no hello). */
function runOutbound(): void {
  const [host, port] = BIND.split(":");
  const server = new WebSocketServer({
    host,
    port: Number(port),
    // Echo the subprotocol siphon offers on the dial (required — the client
    // rejects the handshake otherwise).
    handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
    // Verify the bearer token siphon presents (the app's own policy).
    verifyClient: ({ req }, done) => {
      const ok = req.headers["authorization"] === `Bearer ${TOKEN}`;
      done(ok, 401, "unauthorized");
    },
  });
  server.on("connection", (socket) => {
    console.log("[control] siphon dialed in (outbound per-call-connect) — we own this call");
    new ControlSession(socket); // the first frame is StasisStart
  });
  console.log(`[control] listening (outbound per-call-connect) on ws://${BIND}`);
}

function main(): void {
  if (MODE === "inbound") runInbound();
  else if (MODE === "outbound") runOutbound();
  else throw new Error(`SIPHON_CONTROL_MODE must be 'outbound' or 'inbound' (got ${MODE})`);
}

main();
