/**
 * One live WebSocket connection: request-id correlation, the read path, and
 * generic event fan-out. Knows nothing about SIP — it moves opaque `{module,
 * verb, target, args}` frames and hands every event to a sink.
 *
 * Shared verbatim by the inbound client and the per-call-connect server; only
 * how the socket is *acquired* differs. Mirrors the Rust `SessionCore`.
 */

import type { RawData, WebSocket } from "ws";

import { ControlError } from "./errors";
import type { IdCounter } from "./internal";
import { encodeCommand, parseInboundFrame } from "./protocol";
import type { EventFrame } from "./protocol";

/** A sink the read path calls for every inbound event frame (any module). */
export type EventSink = (frame: EventFrame) => void;

/**
 * Anything that can send a control command and await its correlated reply.
 *
 * Implemented by {@link Session} (bound to one connection — the per-call-connect
 * server) and by the client's commander (routes to the current session,
 * surviving reconnects — the inbound client). Lets a facade's handle command its
 * call without caring which mode it runs in.
 */
export interface CommandTransport {
  command(
    module: string | null,
    verb: string,
    target: unknown,
    args: unknown,
  ): Promise<unknown>;
}

interface Pending {
  resolve: (result: unknown) => void;
  reject: (error: ControlError) => void;
  timer: ReturnType<typeof setTimeout>;
}

/** The shared, transport-agnostic state of one connection. */
export class Session implements CommandTransport {
  private readonly pending = new Map<string, Pending>();
  private closed = false;
  private readonly closeWaiters: Array<() => void> = [];

  constructor(
    private readonly socket: WebSocket,
    private readonly nextId: IdCounter,
    private readonly replyTimeoutMs: number,
    private readonly eventSink: EventSink,
  ) {
    socket.on("message", (data: RawData) => this.onMessage(data.toString()));
    socket.on("close", () => this.markClosed());
    socket.on("error", () => this.markClosed());
  }

  /**
   * Send a command and await its correlated reply. Maps a `status:"error"`
   * reply to a rejected {@link ControlError} carrying the wire code.
   */
  command(
    module: string | null,
    verb: string,
    target: unknown,
    args: unknown,
  ): Promise<unknown> {
    if (this.closed) {
      return Promise.reject(ControlError.closed());
    }
    const id = `c-${this.nextId.value++}`;
    const text = encodeCommand(id, module, verb, target, args);
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(ControlError.timeout(this.replyTimeoutMs));
      }, this.replyTimeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.socket.send(text);
      } catch (error) {
        this.pending.delete(id);
        clearTimeout(timer);
        reject(ControlError.websocket(String(error)));
      }
    });
  }

  private onMessage(text: string): void {
    const frame = parseInboundFrame(text);
    if (frame === null) {
      return;
    }
    if (frame.type === "reply") {
      const pending = this.pending.get(frame.id);
      if (!pending) {
        return; // reply for an unknown / expired id — drop.
      }
      this.pending.delete(frame.id);
      clearTimeout(pending.timer);
      if (frame.status === "ok") {
        pending.resolve(frame.result ?? null);
      } else {
        const code = frame.error?.code ?? "protocol_error";
        const message = frame.error?.message ?? "error reply without an error body";
        pending.reject(ControlError.command(code, message));
      }
    } else {
      this.eventSink(frame);
    }
  }

  /** Explicitly close the connection. */
  close(): void {
    try {
      this.socket.close();
    } catch {
      // ignore — already closing / closed.
    }
    this.markClosed();
  }

  private markClosed(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(ControlError.closed());
    }
    this.pending.clear();
    for (const waiter of this.closeWaiters.splice(0)) {
      waiter();
    }
  }

  isClosed(): boolean {
    return this.closed;
  }

  /** Resolve once the connection is closed. */
  waitClosed(): Promise<void> {
    if (this.closed) {
      return Promise.resolve();
    }
    return new Promise((resolve) => this.closeWaiters.push(resolve));
  }
}
