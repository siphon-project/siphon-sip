/**
 * Example external control client for the siphon control plane (experimental).
 *
 * Connects to siphon's control WebSocket, registers as an application, and drives
 * calls that a B2BUA script hands over with `call.handover("ivr-app")` (the ARI
 * *Stasis* model). Calls that are not handed over are unaffected.
 *
 * The proof-of-concept exposes two verbs, `answer` and `hangup`; this app answers
 * each handed-over call, holds it briefly, then hangs up. Later phases add
 * play / dtmf / bridge / originate over the same protocol.
 *
 * Usage:
 *   npm install
 *   IVR_APP_TOKEN=changeme-dev-token npm start
 *
 * See README.md for the matching siphon `control:` config and handover script.
 */
import WebSocket from "ws";

const CONTROL_URL = process.env.SIPHON_CONTROL_URL ?? "ws://127.0.0.1:9092/control/ws";
const APP_NAME = process.env.SIPHON_CONTROL_APP ?? "ivr-app";
const TOKEN = process.env.IVR_APP_TOKEN ?? "changeme-dev-token";
const ANSWER_HOLD_MS = 5000;

interface ReplyFrame {
  id: string;
  type: "reply";
  status: "ok" | "error";
  result?: unknown;
  error?: { code: string; message: string };
}

interface EventFrame {
  type: "event";
  event: string;
  channel?: string;
  app?: string;
  payload?: unknown;
}

type InboundFrame = ReplyFrame | EventFrame;

/** A minimal control-plane client with request/reply correlation. */
class ControlClient {
  private nextId = 1;
  private readonly pending = new Map<string, (reply: ReplyFrame) => void>();

  constructor(private readonly socket: WebSocket) {
    socket.on("message", (data) => this.onMessage(data.toString()));
  }

  /** Send a command and resolve with its correlated reply frame. */
  rpc(verb: string, target: unknown = {}, args: unknown = {}): Promise<ReplyFrame> {
    const id = `c-${this.nextId++}`;
    return new Promise((resolve) => {
      this.pending.set(id, resolve);
      this.socket.send(JSON.stringify({ id, type: "command", verb, target, args }));
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
      // Handle each event concurrently so a long call flow never blocks the
      // read loop (and thus never stalls other calls).
      void this.onEvent(frame);
    }
  }

  private async onEvent(event: EventFrame): Promise<void> {
    if (event.event === "StasisStart" && event.channel) {
      console.log(`[event] StasisStart ${event.channel}`, event.payload ?? {});
      await this.handleCall(event.channel);
    } else {
      console.log(`[event] ${event.event} ${event.channel ?? ""}`);
    }
  }

  private async handleCall(channel: string): Promise<void> {
    const target = { channel };
    const answered = await this.rpc("answer", target);
    if (answered.status !== "ok") {
      console.log("[call] answer rejected:", answered.error);
      return;
    }
    console.log(`[call] answered ${channel}; holding for ${ANSWER_HOLD_MS}ms`);
    await new Promise((resolve) => setTimeout(resolve, ANSWER_HOLD_MS));
    const hung = await this.rpc("hangup", target);
    console.log(`[call] hangup ${channel}: ${hung.status}`);
  }

  /** Register this connection as APP_NAME (the hello handshake). */
  async register(): Promise<void> {
    const hello = await this.rpc("hello", {}, { app: APP_NAME, protocol: 1 });
    if (hello.status !== "ok") {
      throw new Error(`hello rejected: ${JSON.stringify(hello.error)}`);
    }
    console.log(`[control] registered as ${APP_NAME}`);
  }
}

function main(): void {
  const socket = new WebSocket(CONTROL_URL, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });
  const client = new ControlClient(socket);
  socket.on("open", () => {
    console.log(`[control] connected to ${CONTROL_URL}`);
    client.register().catch((error) => {
      console.error(error);
      socket.close();
    });
  });
  socket.on("error", (error) => console.error("[control] socket error:", error));
  socket.on("close", () => console.log("[control] connection closed"));
}

main();
