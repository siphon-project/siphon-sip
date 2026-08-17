/**
 * Outbound per-call-connect mode: siphon *dials the application* at handover,
 * so the app is a WebSocket **server**. This is the documented default for
 * multi-pod controllers — the accepting socket owns exactly that one call, so
 * "the audio lands on the wrong pod" is structurally impossible.
 *
 * No `hello` is exchanged: siphon presents the token in the dial headers, and
 * the first frame the app receives is a pushed event (`StasisStart` for SIP).
 * Mirrors the Rust `ControlServer`.
 */

import type { AddressInfo } from "node:net";

import WebSocket, { WebSocketServer } from "ws";

import { ControlError } from "./errors";
import type { IdCounter } from "./internal";
import { SUBPROTOCOL } from "./protocol";
import type { EventFrame } from "./protocol";
import type { CommandTransport, EventSink } from "./session";
import { Session } from "./session";

/** How a {@link ControlServer} listens for siphon's per-call dials. */
export interface ServerConfig {
  /** The host to bind (e.g. `0.0.0.0`). */
  host: string;
  /** The port to bind (`0` picks a free port — read it back via `localAddr`). */
  port: number;
  /** The application name (context / logging). */
  app: string;
  /** The bearer token siphon must present on the dial. */
  token: string;
  /** How long a command waits for its reply before a timeout (default 10 000 ms). */
  replyTimeoutMs?: number;
}

/** A sink the server calls for each event, carrying the {@link CommandTransport}
 * of the connection that produced it (so a facade commands back on the right one). */
export type ConnectionEventSink = (frame: EventFrame, transport: CommandTransport) => void;

/** The protocol-agnostic per-call-connect control server. */
export class ControlServer {
  private readonly nextId: IdCounter = { value: 1 };
  private eventSink: ConnectionEventSink | null = null;
  private readonly closeWaiters: Array<() => void> = [];
  private readonly sockets = new Set<WebSocket>();
  private closed = false;

  private constructor(
    private readonly config: ServerConfig,
    private readonly wss: WebSocketServer,
  ) {
    wss.on("connection", (socket, request) => this.onConnection(socket, request));
    wss.on("close", () => this.markClosed());
  }

  /** Bind the listener (so the assigned port is known before accepting). */
  static bind(config: ServerConfig): Promise<ControlServer> {
    const token = config.token;
    return new Promise<ControlServer>((resolve, reject) => {
      const wss = new WebSocketServer({
        host: config.host,
        port: config.port,
        // Echo the subprotocol siphon offers on the dial (required — the client
        // rejects the handshake otherwise).
        handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
        // Verify the bearer token siphon presents (the app's own policy).
        verifyClient: ({ req }, done) => {
          const ok = req.headers["authorization"] === `Bearer ${token}`;
          done(ok, 401, "unauthorized");
        },
      });
      const onError = (error: Error): void => {
        wss.off("listening", onListening);
        reject(ControlError.config(`bind ${config.host}:${config.port}: ${error.message}`));
      };
      const onListening = (): void => {
        wss.off("error", onError);
        resolve(new ControlServer(config, wss));
      };
      wss.once("listening", onListening);
      wss.once("error", onError);
    });
  }

  /** The actual bound address (useful when binding to port 0 in tests). */
  localAddr(): AddressInfo {
    const address = this.wss.address();
    if (typeof address === "string" || address === null) {
      throw ControlError.config("server is not bound to a TCP address");
    }
    return address;
  }

  /** Register the sink for `(event, connection-commander)` pairs. Facades set this internally. */
  onConnectionEvent(sink: ConnectionEventSink): void {
    this.eventSink = sink;
  }

  /** Resolve once the server has been closed (`run` resolves at the same time). */
  run(): Promise<void> {
    if (this.closed) {
      return Promise.resolve();
    }
    return new Promise((resolve) => this.closeWaiters.push(resolve));
  }

  /** Stop accepting dials, drop live connections, and close the listener. */
  close(): Promise<void> {
    // Terminate live connections first: the underlying HTTP server's `close`
    // does not fire until every connection has ended.
    for (const socket of this.sockets) {
      socket.terminate();
    }
    this.sockets.clear();
    return new Promise((resolve) => {
      this.wss.close(() => {
        this.markClosed();
        resolve();
      });
    });
  }

  private markClosed(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const waiter of this.closeWaiters.splice(0)) {
      waiter();
    }
  }

  private onConnection(socket: WebSocket, _request: unknown): void {
    this.sockets.add(socket);
    socket.on("close", () => this.sockets.delete(socket));
    // The event sink needs this connection's commander, which is the session
    // itself. `session` is assigned synchronously here, before any inbound
    // message can be delivered (those arrive on later ticks).
    let session: Session;
    const sink: EventSink = (frame) => {
      this.eventSink?.(frame, session);
    };
    session = new Session(socket, this.nextId, this.config.replyTimeoutMs ?? 10_000, sink);
  }
}
