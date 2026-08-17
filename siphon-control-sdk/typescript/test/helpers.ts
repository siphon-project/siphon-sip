/** A tiny in-process stub of siphon's control WebSocket, for correlation tests. */

import type { AddressInfo } from "node:net";

import { WebSocketServer } from "ws";
import type { WebSocket } from "ws";

import { SUBPROTOCOL } from "../src/index";

/** The shape a stub sees for an inbound command frame. */
export interface CommandFrameLike {
  id: string;
  type: string;
  module?: string;
  verb: string;
  target?: { channel?: string } | null;
  args?: Record<string, unknown> | null;
}

/** A reply body the stub returns for a command (`undefined` = deliberately drop). */
export type ReplyBody =
  | { status: "ok"; result?: unknown }
  | { status: "error"; error: { code: string; message: string } };

export interface StubOptions {
  /** Reject the upgrade unless the bearer token matches this (per-call-connect style). */
  token?: string;
  /** Per-command reply logic; return `undefined` to drop (for timeout tests). */
  onCommand?: (frame: CommandFrameLike, socket: WebSocket) => ReplyBody | undefined;
  /** Channels returned from a `resync`. */
  resyncChannels?: unknown[];
  /** Auto-answer the `hello` handshake (default true). */
  autoHello?: boolean;
}

/** A protocol-speaking WebSocket stub the SDK's client can connect to. */
export class ControlStub {
  /** Every command frame the stub received, in order. */
  readonly received: CommandFrameLike[] = [];
  private readonly sockets = new Set<WebSocket>();

  private constructor(
    private readonly wss: WebSocketServer,
    private readonly options: StubOptions,
  ) {}

  static async start(options: StubOptions = {}): Promise<ControlStub> {
    const wss = new WebSocketServer({
      host: "127.0.0.1",
      port: 0,
      handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
      verifyClient:
        options.token === undefined
          ? undefined
          : ({ req }, done) => done(req.headers.authorization === `Bearer ${options.token}`, 401),
    });
    const stub = new ControlStub(wss, options);
    wss.on("connection", (socket) => stub.onConnection(socket));
    await new Promise<void>((resolve, reject) => {
      wss.once("listening", () => resolve());
      wss.once("error", reject);
    });
    return stub;
  }

  address(): AddressInfo {
    const address = this.wss.address();
    if (address === null || typeof address === "string") {
      throw new Error("stub is not bound to a TCP port");
    }
    return address;
  }

  url(): string {
    return `ws://127.0.0.1:${this.address().port}/control/ws`;
  }

  private onConnection(socket: WebSocket): void {
    this.sockets.add(socket);
    socket.on("close", () => this.sockets.delete(socket));
    socket.on("message", (data) => {
      const frame = JSON.parse(data.toString()) as CommandFrameLike;
      if (frame.type !== "command") {
        return;
      }
      this.received.push(frame);
      const reply = this.replyFor(frame, socket);
      if (reply) {
        socket.send(JSON.stringify({ id: frame.id, type: "reply", ...reply }));
      }
    });
  }

  private replyFor(frame: CommandFrameLike, socket: WebSocket): ReplyBody | undefined {
    if (frame.verb === "hello" && (this.options.autoHello ?? true)) {
      const args = frame.args ?? {};
      return {
        status: "ok",
        result: {
          app: (args.app as string) ?? "app",
          protocol: (args.protocol as number) ?? 1,
          subprotocol: SUBPROTOCOL,
        },
      };
    }
    if (frame.verb === "resync") {
      return { status: "ok", result: { channels: this.options.resyncChannels ?? [] } };
    }
    if (this.options.onCommand) {
      return this.options.onCommand(frame, socket);
    }
    return { status: "ok", result: {} };
  }

  /** Push an event frame to every connected socket (or a specific one). */
  pushEvent(event: Record<string, unknown>, socket?: WebSocket): void {
    const targets = socket ? [socket] : [...this.sockets];
    for (const target of targets) {
      target.send(JSON.stringify({ type: "event", ...event }));
    }
  }

  connectionCount(): number {
    return this.sockets.size;
  }

  async stop(): Promise<void> {
    for (const socket of this.sockets) {
      socket.terminate();
    }
    await new Promise<void>((resolve) => this.wss.close(() => resolve()));
  }
}

/** Poll `predicate` until it is true, or throw after `timeoutMs`. */
export async function waitFor(
  predicate: () => boolean,
  timeoutMs = 1000,
  stepMs = 5,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error("waitFor: condition not met before timeout");
    }
    await new Promise((resolve) => setTimeout(resolve, stepMs));
  }
}
