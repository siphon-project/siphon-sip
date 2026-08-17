/**
 * The protocol-agnostic inbound-persistent control client.
 *
 * Knows nothing about SIP: it owns the transport, the `hello` handshake,
 * request-id correlation, reconnect + `resync`, and a generic event stream. Its
 * headline primitive is {@link ControlClient.command} over `{module, verb,
 * target, args}`, which works for any adapter with zero changes. Typed
 * per-protocol facades (see {@link SipClient}) are built on top. Mirrors the
 * Rust `ControlClient`.
 */

import WebSocket from "ws";

import { ControlError } from "./errors";
import type { IdCounter } from "./internal";
import { AsyncQueue, sleep } from "./internal";
import {
  DESCRIBE,
  HELLO,
  PROTOCOL_VERSION,
  RESYNC,
  SUBPROTOCOL,
} from "./protocol";
import type {
  ChannelSnapshot,
  EventFrame,
  HelloResult,
  ResyncResult,
} from "./protocol";
import type { CommandTransport } from "./session";
import { Session } from "./session";

/** How a {@link ControlClient} connects and behaves. */
export interface ClientConfig {
  /** The control-plane URL, e.g. `ws://siphon:9090/control/ws` (or `wss://…`). */
  url: string;
  /** The application name — must equal the token's configured app. */
  app: string;
  /** The bearer token presented on the upgrade. */
  token: string;
  /** Protocol version to advertise in `hello` (defaults to {@link PROTOCOL_VERSION}). */
  protocol?: number;
  /** How long a command waits for its reply before a timeout (default 10 000 ms). */
  replyTimeoutMs?: number;
  /** Backoff between reconnect attempts in {@link ControlClient.run} (default 1 000 ms). */
  reconnectBackoffMs?: number;
}

type ResolvedConfig = Required<ClientConfig>;

function resolveConfig(config: ClientConfig): ResolvedConfig {
  return {
    url: config.url,
    app: config.app,
    token: config.token,
    protocol: config.protocol ?? PROTOCOL_VERSION,
    replyTimeoutMs: config.replyTimeoutMs ?? 10_000,
    reconnectBackoffMs: config.reconnectBackoffMs ?? 1_000,
  };
}

/** An item on the client's generic event stream. */
export type ClientEvent =
  | { type: "event"; frame: EventFrame }
  | { type: "reattach"; snapshot: ChannelSnapshot };

type EventCallback = (event: ClientEvent) => void;

/** A generic subscription to the client's event stream (see {@link ControlClient.events}). */
export class EventStream {
  constructor(private readonly queue: AsyncQueue<ClientEvent>) {}

  /** Await the next event. `null` once the client shuts down. */
  next(): Promise<ClientEvent | null> {
    return this.queue.next();
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<ClientEvent> {
    return this.queue[Symbol.asyncIterator]();
  }
}

/**
 * The protocol-agnostic inbound-persistent control client.
 *
 * Use {@link ControlClient.command} directly for any module, or wrap it in a
 * typed facade such as {@link SipClient}.
 */
export class ControlClient {
  private readonly config: ResolvedConfig;
  private readonly nextId: IdCounter = { value: 1 };
  private current: Session | null = null;
  private eventCallback: EventCallback | null = null;
  private shutdownRequested = false;
  private readonly shutdownWaiters: Array<() => void> = [];

  private constructor(config: ClientConfig) {
    this.config = resolveConfig(config);
  }

  /**
   * Connect + `hello`. A bad token surfaces as a {@link ControlError} of kind
   * `unauthorized` (the upgrade is rejected 401 before the socket opens).
   */
  static async connect(config: ClientConfig): Promise<ControlClient> {
    const client = new ControlClient(config);
    client.current = await client.connectAndHandshake();
    return client;
  }

  /**
   * Register a callback for every event (pushed events + reconnect reattach).
   * Overwrites any previous callback / stream. Facades set this internally.
   */
  onEvent(callback: EventCallback): void {
    this.eventCallback = callback;
  }

  /** A pull-style stream of every event. Overwrites any previous callback. */
  events(): EventStream {
    const queue = new AsyncQueue<ClientEvent>();
    this.eventCallback = (event) => queue.push(event);
    return new EventStream(queue);
  }

  /**
   * Send a raw command on the current session and return the reply's `result`.
   * The generic primitive every facade is built on.
   */
  async command(
    module: string | null,
    verb: string,
    target: unknown,
    args: unknown,
  ): Promise<unknown> {
    const session = this.current;
    if (!session || session.isClosed()) {
      throw ControlError.closed();
    }
    return session.command(module, verb, target, args);
  }

  /** Fetch the registered adapters' verb/event schema (`describe`). */
  async describe(): Promise<unknown> {
    return this.command(null, DESCRIBE, null, null);
  }

  /** Re-enumerate the channels this connection owns (`resync`). */
  async resync(): Promise<ChannelSnapshot[]> {
    const value = (await this.command(null, RESYNC, null, null)) as ResyncResult | null;
    return value?.channels ?? [];
  }

  /**
   * A {@link CommandTransport} that routes to the client's *current* session (so
   * a facade handle keeps working across reconnects). Used by {@link SipClient}.
   */
  commander(): CommandTransport {
    return {
      command: (module, verb, target, args) => this.command(module, verb, target, args),
    };
  }

  /**
   * Drive the client: keep the connection alive, reconnecting with backoff and
   * re-attaching owned channels (`resync`, delivered as `reattach` events) after
   * each reconnect. Resolves on {@link ControlClient.shutdown}, or rejects on a
   * fatal error (token revoked → `unauthorized`).
   */
  async run(): Promise<void> {
    for (;;) {
      let session = this.current;
      if (!session || session.isClosed()) {
        if (this.shutdownRequested) {
          return;
        }
        try {
          session = await this.connectAndHandshake();
        } catch (error) {
          if (error instanceof ControlError && error.kind === "unauthorized") {
            throw error;
          }
          await Promise.race([sleep(this.config.reconnectBackoffMs), this.shutdownSignal()]);
          if (this.shutdownRequested) {
            return;
          }
          continue;
        }
        this.current = session;
        await this.resyncAndReattach(session);
      }

      await Promise.race([session.waitClosed(), this.shutdownSignal()]);
      if (this.shutdownRequested) {
        return;
      }
      this.current = null;
    }
  }

  /** Stop the client: close the current session and unblock {@link ControlClient.run}. */
  shutdown(): void {
    this.shutdownRequested = true;
    for (const waiter of this.shutdownWaiters.splice(0)) {
      waiter();
    }
    if (this.current) {
      this.current.close();
      this.current = null;
    }
  }

  private shutdownSignal(): Promise<void> {
    if (this.shutdownRequested) {
      return Promise.resolve();
    }
    return new Promise((resolve) => this.shutdownWaiters.push(resolve));
  }

  private emit(event: ClientEvent): void {
    this.eventCallback?.(event);
  }

  private async connectAndHandshake(): Promise<Session> {
    const socket = await this.openSocket();
    const session = new Session(
      socket,
      this.nextId,
      this.config.replyTimeoutMs,
      (frame) => this.emit({ type: "event", frame }),
    );
    const result = (await session.command(null, HELLO, null, {
      app: this.config.app,
      protocol: this.config.protocol,
    })) as HelloResult | null;
    if (!result || result.subprotocol !== SUBPROTOCOL) {
      session.close();
      throw ControlError.handshake(
        `server negotiated subprotocol ${JSON.stringify(result?.subprotocol)}, expected ${JSON.stringify(SUBPROTOCOL)}`,
      );
    }
    return session;
  }

  private openSocket(): Promise<WebSocket> {
    return new Promise<WebSocket>((resolve, reject) => {
      const socket = new WebSocket(this.config.url, [SUBPROTOCOL], {
        headers: { Authorization: `Bearer ${this.config.token}` },
      });
      let settled = false;
      const settle = (): void => {
        settled = true;
        socket.off("open", onOpen);
        socket.off("unexpected-response", onUnexpected);
      };
      const onOpen = (): void => {
        settle();
        resolve(socket);
      };
      const onUnexpected = (
        request: { destroy: () => void },
        response: { statusCode?: number },
      ): void => {
        settle();
        // Free the aborted upgrade's socket without the "closed before the
        // connection was established" that `socket.terminate()` throws here.
        request.destroy();
        reject(ControlError.unauthorized(response.statusCode ?? 0));
      };
      const onError = (error: Error): void => {
        if (!settled) {
          settle();
          reject(ControlError.websocket(error.message));
        }
        // Post-settle errors (e.g. the destroyed handshake socket hanging up)
        // are swallowed here so a stray `error` never crashes the process.
      };
      socket.on("open", onOpen);
      socket.on("unexpected-response", onUnexpected);
      socket.on("error", onError);
    });
  }

  private async resyncAndReattach(session: Session): Promise<void> {
    try {
      const value = (await session.command(null, RESYNC, null, null)) as ResyncResult | null;
      for (const snapshot of value?.channels ?? []) {
        this.emit({ type: "reattach", snapshot });
      }
    } catch {
      // A failed resync is non-fatal — the connection stays up.
    }
  }
}
