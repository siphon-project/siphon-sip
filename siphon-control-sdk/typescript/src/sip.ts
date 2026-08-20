/**
 * The **SIP facade** over the protocol-agnostic core.
 *
 * {@link Call} is a typed handle whose verbs (`answer`/`progress`/`reject`/
 * `terminate`/`refer`/…) are thin wrappers that send `command("sip", …)` on the
 * underlying core and await the correlated reply. The method names mirror the
 * in-process siphon scripting API (`call.answer()`, `call.terminate()`,
 * `call.transfer()`, `call.setHeader()`, …), so an out-of-process controller
 * reads like an in-process script. The `StasisStart`→{@link Call} dispatch and
 * the `onCall` handler live here (they are SIP/ARI concepts) on top of the
 * core's generic event stream, so a future `smpp` / `ss7` facade is an additive
 * sibling over the same core.
 */

import type { ControlClient, ClientConfig, ClientEvent } from "./client";
import { ControlClient as ControlClientImpl } from "./client";
import { AsyncQueue } from "./internal";
import {
  MODULE_SIP,
  SET_VAR,
  GET_VAR,
  SipVerb,
  sipEventKind,
} from "./protocol";
import type {
  ChannelSnapshot,
  EventFrame,
  SipEventKind,
} from "./protocol";
import type { ControlServer, ServerConfig } from "./server";
import { ControlServer as ControlServerImpl } from "./server";
import type { CommandTransport } from "./session";

// ---------------------------------------------------------------------------
// Call handle
// ---------------------------------------------------------------------------

/** One event delivered to a call's stream (`ChannelStateChange`,
 * `ChannelHangupRequest`, `ChannelDtmfReceived`, `TransferRequested`,
 * `StasisEnd`, …). Cast `payload` to
 * {@link import("./protocol").ChannelDtmfPayload} /
 * {@link import("./protocol").TransferRequestedPayload} by `kind`. */
export interface CallEvent {
  /** The parsed event kind. */
  kind: SipEventKind;
  /** The event-specific payload. */
  payload: unknown;
  /** The raw frame (for fields not surfaced above). */
  frame: EventFrame;
}

function callEventFromFrame(frame: EventFrame): CallEvent {
  return { kind: sipEventKind(frame.event), payload: frame.payload ?? null, frame };
}

/** Options for a UAS provisional / final response (`answer` / `progress`). */
export interface ResponseOptions {
  code?: number;
  reason?: string;
  body?: string;
  contentType?: string;
}

function responseArgs(options: ResponseOptions): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  if (options.code !== undefined) {
    args.code = options.code;
  }
  if (options.reason !== undefined) {
    args.reason = options.reason;
  }
  if (options.body !== undefined) {
    args.body = options.body;
  }
  if (options.contentType !== undefined) {
    args.content_type = options.contentType;
  }
  return args;
}

/** The RFC 3891 `Replaces` triple for an attended transfer. */
export interface ReferReplaces {
  callId: string;
  fromTag: string;
  toTag: string;
  earlyOnly?: boolean;
}

/** Options for {@link Call.acceptRefer}. */
export interface AcceptReferOptions {
  target?: string;
  nextHop?: string;
  mode?: "terminate" | "transparent";
}

/** A {@link Call.route} target carrying per-target overrides. */
export interface RouteTargetObject {
  /** The B-leg request URI to dial. */
  uri: string;
  /** Route egress to this next hop instead of resolving `uri`. */
  nextHop?: string;
  /** Headers injected on this attempt's B-leg INVITE. */
  headers?: Record<string, string>;
  /** Per-target ring timeout in seconds. */
  timeout?: number;
}

/**
 * One entry in a {@link Call.route} target list: a bare URI string, or a
 * {@link RouteTargetObject} with per-target overrides.
 */
export type RouteTarget = string | RouteTargetObject;

function routeTargetToWire(target: RouteTarget): unknown {
  if (typeof target === "string") {
    return target;
  }
  const object: Record<string, unknown> = { uri: target.uri };
  if (target.nextHop !== undefined) {
    object.next_hop = target.nextHop;
  }
  if (target.headers !== undefined) {
    object.headers = target.headers;
  }
  if (target.timeout !== undefined) {
    object.timeout = target.timeout;
  }
  return object;
}

function stringValue(result: unknown): string | null {
  if (typeof result === "object" && result !== null) {
    const value = (result as { value?: unknown }).value;
    if (typeof value === "string") {
      return value;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// play() / dtmf() / streamStart() args
// ---------------------------------------------------------------------------

/**
 * The audio source for {@link Call.play}: exactly one of a server-side file
 * path, an rtpengine media-DB id, or an inline blob. A blob is base64-encoded on
 * the wire (the control rail is JSON text).
 */
export type PlaySource =
  | { file: string }
  | { dbId: number }
  | { blob: Uint8Array };

/** Optional shaping for {@link Call.play}. */
export interface PlayOptions {
  /** Repeat the prompt this many times (0/undefined → play once). */
  repeat?: number;
  /** Start playback at this offset into the source, in milliseconds. */
  startMs?: number;
  /** Cap playback to this duration, in milliseconds. */
  durationMs?: number;
  /** Scope the prompt to one peer of an MPTY bridge (its To-tag). */
  toTag?: string;
}

/** Optional shaping for {@link Call.dtmf}. */
export interface DtmfOptions {
  /** Per-digit tone duration, in milliseconds. */
  durationMs?: number;
  /** Tone volume in dBm0 (negative). */
  volumeDbm0?: number;
  /** Inter-digit pause, in milliseconds. */
  pauseMs?: number;
  /** Scope the tones to one peer of an MPTY bridge (its To-tag). */
  toTag?: string;
}

/** Options for {@link Call.streamStart} (the WebSocket audio tee). */
export interface StreamOptions {
  /** Which leg(s) to tee — `"both"` (default), `"caller"`, or `"callee"`. */
  direction?: "both" | "caller" | "callee";
  /** `1` = mixed mono, `2` = caller/callee stereo (only with `"both"`). */
  channels?: 1 | 2;
}

function playArgs(source: PlaySource, options?: PlayOptions): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  if ("file" in source) {
    args.file = source.file;
  } else if ("dbId" in source) {
    args.db_id = source.dbId;
  } else {
    args.blob = Buffer.from(source.blob).toString("base64");
  }
  if (options?.repeat !== undefined) {
    args.repeat = options.repeat;
  }
  if (options?.startMs !== undefined) {
    args.start_ms = options.startMs;
  }
  if (options?.durationMs !== undefined) {
    args.duration_ms = options.durationMs;
  }
  if (options?.toTag !== undefined) {
    args.to_tag = options.toTag;
  }
  return args;
}

function dtmfArgs(digits: string, options?: DtmfOptions): Record<string, unknown> {
  const args: Record<string, unknown> = { digits };
  if (options?.durationMs !== undefined) {
    args.duration_ms = options.durationMs;
  }
  if (options?.volumeDbm0 !== undefined) {
    args.volume_dbm0 = options.volumeDbm0;
  }
  if (options?.pauseMs !== undefined) {
    args.pause_ms = options.pauseMs;
  }
  if (options?.toTag !== undefined) {
    args.to_tag = options.toTag;
  }
  return args;
}

/**
 * A handed-over SIP call. Cheap to hold (shares one connection + event stream).
 * Verb names mirror the in-process `call.*` scripting API.
 */
export class Call {
  constructor(
    private readonly transport: CommandTransport,
    /** The leg-scoped channel id — the address for every verb on this call. */
    readonly channelId: string,
    /** The internal `CallActor` id (the grouping key across legs), if known. */
    readonly callId: string | null,
    /** The per-leg SIP `Call-ID` — byte-identical to the CDR / HEP join key. */
    readonly sipCallId: string | null,
    /** The application this call was handed to. */
    readonly app: string | null,
    /** The `StasisStart` payload (full SIP context), or the `resync` snapshot. */
    readonly payload: unknown,
    /** True when this call came from a `resync` re-attach after a reconnect. */
    readonly reattached: boolean,
    private readonly eventQueue: AsyncQueue<CallEvent>,
  ) {}

  private target(): { channel: string } {
    return { channel: this.channelId };
  }

  private sip(verb: string, args: unknown): Promise<unknown> {
    return this.transport.command(MODULE_SIP, verb, this.target(), args);
  }

  private substrate(verb: string, args: unknown): Promise<unknown> {
    return this.transport.command(null, verb, this.target(), args);
  }

  // --- SIP verbs (mirror the in-process scripting API) -------------------

  /** Send a UAS 2xx to the parked A-leg (default `200 OK`). */
  async answer(options?: ResponseOptions): Promise<void> {
    await this.sip(SipVerb.Answer, options ? responseArgs(options) : {});
  }

  /** Send a UAS 1xx / early media (default `183 Session Progress`). */
  async progress(options?: ResponseOptions): Promise<void> {
    await this.sip(SipVerb.Progress, options ? responseArgs(options) : {});
  }

  /** Send a final non-2xx and tear the call down. */
  async reject(code: number, reason?: string): Promise<void> {
    const args: Record<string, unknown> = { code };
    if (reason !== undefined) {
      args.reason = reason;
    }
    await this.sip(SipVerb.Reject, args);
  }

  /**
   * Tear the call down: BYE an answered call (full teardown funnel), or reject
   * an unanswered one. Mirrors the in-process `call.terminate()`.
   */
  async terminate(reason?: string): Promise<void> {
    await this.sip(SipVerb.Hangup, reason !== undefined ? { reason } : {});
  }

  /** Alias for {@link Call.terminate}. */
  async hangup(reason?: string): Promise<void> {
    await this.terminate(reason);
  }

  /** Send an in-dialog REFER on the A-leg (blind transfer). */
  async refer(to: string): Promise<void> {
    await this.sip(SipVerb.Refer, { to });
  }

  /** Blind-transfer alias for {@link Call.refer}. */
  async transfer(to: string): Promise<void> {
    await this.refer(to);
  }

  /** Attended transfer — REFER with a `Replaces` triple (RFC 3891). */
  async referReplaces(to: string, replaces: ReferReplaces): Promise<void> {
    await this.sip(SipVerb.Refer, {
      to,
      replaces: {
        call_id: replaces.callId,
        from_tag: replaces.fromTag,
        to_tag: replaces.toTag,
        early_only: replaces.earlyOnly ?? false,
      },
    });
  }

  /**
   * Un-park this controlled call and dial the B-leg via siphon's LCR
   * sequential-failover engine, returning control to siphon.
   *
   * `targets` is a non-empty list of carriers tried cheapest-first: each entry
   * is a bare URI string or a {@link RouteTargetObject}
   * (`{uri, nextHop?, headers?, timeout?}`). `strategy` defaults to
   * `"sequential"` (v1 supports only sequential/single — anything else rejects
   * with `code === "unsupported_verb"`). `headers` is applied to every
   * attempt's B-leg INVITE.
   *
   * Resolves to the reply `result` (`{channel, state: "routing", targets}`). An
   * empty / invalid `targets` list rejects with `code === "bad_request"`; a call
   * that is already gone rejects with `code === "not_found"`.
   */
  async route(
    targets: RouteTarget[],
    strategy = "sequential",
    headers?: Record<string, string>,
  ): Promise<unknown> {
    const args: Record<string, unknown> = {
      targets: targets.map(routeTargetToWire),
      strategy,
    };
    if (headers !== undefined) {
      args.headers = headers;
    }
    return this.sip(SipVerb.Route, args);
  }

  /**
   * Accept a *pending inbound* REFER (surfaced as a `TransferRequested` event)
   * and run the transfer. `target` overrides the Refer-To URI, `nextHop` steers
   * egress, and `mode` (`"terminate"` / `"transparent"`) overrides
   * `b2bua.default_refer_mode`. No pending REFER (already decided, timed out, or
   * the call is gone) rejects with `code === "not_found"`.
   */
  async acceptRefer(options?: AcceptReferOptions): Promise<void> {
    const args: Record<string, unknown> = {};
    if (options?.target !== undefined) {
      args.target = options.target;
    }
    if (options?.nextHop !== undefined) {
      args.next_hop = options.nextHop;
    }
    if (options?.mode !== undefined) {
      args.mode = options.mode;
    }
    await this.sip(SipVerb.AcceptRefer, args);
  }

  /**
   * Reject a *pending inbound* REFER with a final non-2xx (default
   * `603 Decline`). No pending REFER rejects with `code === "not_found"`.
   */
  async rejectRefer(code: number, reason?: string): Promise<void> {
    const args: Record<string, unknown> = { code };
    if (reason !== undefined) {
      args.reason = reason;
    }
    await this.sip(SipVerb.RejectRefer, args);
  }

  /** Set a header on the stored A-leg INVITE. */
  async setHeader(name: string, value: string): Promise<void> {
    await this.sip(SipVerb.SetHeader, { name, value });
  }

  /** Read a header from the stored A-leg INVITE (`null` when absent). */
  async getHeader(name: string): Promise<string | null> {
    const result = await this.sip(SipVerb.GetHeader, { name });
    return stringValue(result);
  }

  /** Remove a header from the stored A-leg INVITE. */
  async removeHeader(name: string): Promise<void> {
    await this.sip(SipVerb.RemoveHeader, { name });
  }

  // --- per-call variables (substrate verbs, no module) -------------------

  /** Set a per-call variable (survives a reconnect via `resync`). */
  async setVar(key: string, value: string): Promise<void> {
    await this.substrate(SET_VAR, { key, value });
  }

  /** Read a per-call variable (`null` when unset). */
  async getVar(key: string): Promise<string | null> {
    const result = await this.substrate(GET_VAR, { key });
    return stringValue(result);
  }

  // --- media -------------------------------------------------------------

  /**
   * Play an announcement on the A-leg media (fire-and-forget). `source` is a
   * {@link PlaySource} (a blob is base64-encoded on the wire); `options` shapes
   * playback. A call with no anchored media session rejects with
   * `code === "not_found"`.
   */
  async play(source: PlaySource, options?: PlayOptions): Promise<void> {
    await this.sip(SipVerb.Play, playArgs(source, options));
  }

  /** Convenience for {@link Call.play} of a server-side file with default options. */
  async playFile(file: string): Promise<void> {
    await this.play({ file });
  }

  /** Stop the announcement currently playing on the A-leg media. */
  async stop(): Promise<void> {
    await this.sip(SipVerb.Stop, {});
  }

  /**
   * Inject DTMF digits toward the A-leg (fire-and-forget). `options` carries the
   * optional `durationMs` / `volumeDbm0` / `pauseMs` / `toTag` shaping.
   */
  async dtmf(digits: string, options?: DtmfOptions): Promise<void> {
    await this.sip(SipVerb.Dtmf, dtmfArgs(digits, options));
  }

  /** Hold the A-leg media via silence. */
  async hold(): Promise<void> {
    await this.sip(SipVerb.Hold, {});
  }

  /** Resume the A-leg media after a {@link Call.hold}. */
  async unhold(): Promise<void> {
    await this.sip(SipVerb.Unhold, {});
  }

  /**
   * Attach a WebSocket audio tee — stream a copy of the call's decoded audio to
   * `wsUri` while the call keeps relaying. siphon-rtp backend only: rtpengine /
   * rtpproxy reject with `code === "unsupported_verb"` (`error.isUnsupportedVerb()`).
   */
  async streamStart(wsUri: string, options?: StreamOptions): Promise<void> {
    const args: Record<string, unknown> = { ws_uri: wsUri };
    if (options?.direction !== undefined) {
      args.direction = options.direction;
    }
    if (options?.channels !== undefined) {
      args.channels = options.channels;
    }
    await this.sip(SipVerb.StreamStart, args);
  }

  /** Detach the WebSocket audio tee (idempotent on siphon-rtp). */
  async streamStop(): Promise<void> {
    await this.sip(SipVerb.StreamStop, {});
  }

  // --- escape hatch + events --------------------------------------------

  /** Send an arbitrary SIP-adapter verb + args and return the raw result. */
  async command(verb: string, args?: unknown): Promise<unknown> {
    return this.sip(verb, args ?? {});
  }

  /**
   * Await the next event for this call (`ChannelStateChange`,
   * `ChannelHangupRequest`, `StasisEnd`). `null` once the stream closes.
   */
  nextEvent(): Promise<CallEvent | null> {
    return this.eventQueue.next();
  }

  /** Async-iterate this call's events until the stream closes. */
  events(): AsyncIterableIterator<CallEvent> {
    return this.eventQueue[Symbol.asyncIterator]();
  }
}

// ---------------------------------------------------------------------------
// Call dispatch (handler or pull stream) + per-channel event routing
// ---------------------------------------------------------------------------

/** A per-call handler. Both sync (`void`) and async (`Promise<void>`) supported. */
export type CallHandler = (call: Call) => void | Promise<void>;

/** A pull-style stream of handed-over calls (alternative to a handler). */
export class CallStream {
  constructor(private readonly queue: AsyncQueue<Call>) {}

  /** Await the next handed-over call. `null` once the client/server shuts down. */
  next(): Promise<Call | null> {
    return this.queue.next();
  }

  [Symbol.asyncIterator](): AsyncIterableIterator<Call> {
    return this.queue[Symbol.asyncIterator]();
  }
}

/**
 * The SIP facade's event router: builds `Call`s from `StasisStart`/reattach,
 * routes channel-scoped events to the owning call, and dispatches new calls to a
 * handler or pull stream. Mirrors the Rust `SipFacade`.
 */
class SipFacade {
  private handler: CallHandler | null = null;
  private callQueue: AsyncQueue<Call> | null = null;
  private readonly channels = new Map<string, AsyncQueue<CallEvent>>();

  setHandler(handler: CallHandler): void {
    this.handler = handler;
  }

  setStream(): CallStream {
    const queue = new AsyncQueue<Call>();
    this.callQueue = queue;
    return new CallStream(queue);
  }

  handleClientEvent(event: ClientEvent, transport: CommandTransport): void {
    if (event.type === "event") {
      this.handleEvent(event.frame, transport);
    } else {
      this.reattach(event.snapshot, transport);
    }
  }

  handleEvent(frame: EventFrame, transport: CommandTransport): void {
    const kind = sipEventKind(frame.event);
    if (kind === "StasisStart") {
      if (!frame.channel) {
        return; // StasisStart without a channel — drop.
      }
      const queue = new AsyncQueue<CallEvent>();
      this.channels.set(frame.channel, queue);
      const call = new Call(
        transport,
        frame.channel,
        frame.call_id ?? null,
        frame.sip_call_id ?? null,
        frame.app ?? null,
        frame.payload ?? null,
        false,
        queue,
      );
      this.dispatch(call);
    } else if (kind === "StasisEnd") {
      if (frame.channel) {
        this.route(frame.channel, callEventFromFrame(frame));
        const queue = this.channels.get(frame.channel);
        queue?.close();
        this.channels.delete(frame.channel);
      }
    } else if (frame.channel) {
      this.route(frame.channel, callEventFromFrame(frame));
    }
  }

  private reattach(snapshot: ChannelSnapshot, transport: CommandTransport): void {
    const queue = new AsyncQueue<CallEvent>();
    this.channels.set(snapshot.channel, queue);
    const call = new Call(
      transport,
      snapshot.channel,
      snapshot.call_id,
      snapshot.sip_call_id,
      null,
      snapshot,
      true,
      queue,
    );
    this.dispatch(call);
  }

  private route(channel: string, event: CallEvent): void {
    this.channels.get(channel)?.push(event);
  }

  private dispatch(call: Call): void {
    if (this.handler) {
      const handler = this.handler;
      void Promise.resolve()
        .then(() => handler(call))
        .catch((error: unknown) => {
          // A handler error must never take down the router.
          void error;
        });
    } else if (this.callQueue) {
      this.callQueue.push(call);
    }
    // No handler / stream → the call is dropped (nothing owns it).
  }
}

// ---------------------------------------------------------------------------
// Inbound-persistent SIP facade
// ---------------------------------------------------------------------------

/**
 * The SIP facade over an inbound-persistent {@link ControlClient}.
 *
 * ```ts
 * const client = await SipClient.connect({
 *   url: "ws://siphon:9090/control/ws",
 *   app: "ivr-app",
 *   token: "s3cr3t",
 * });
 * await client.onCall(async (call) => {
 *   await call.answer();
 *   await call.transfer("sip:agent@pbx");
 * });
 * ```
 */
export class SipClient {
  private readonly facade = new SipFacade();

  private constructor(private readonly client: ControlClient) {
    const commander = client.commander();
    client.onEvent((event) => this.facade.handleClientEvent(event, commander));
  }

  /** Connect + `hello`, then install the SIP event router. */
  static async connect(config: ClientConfig): Promise<SipClient> {
    const client = await ControlClientImpl.connect(config);
    return new SipClient(client);
  }

  /** Wrap an already-connected generic client with the SIP facade. */
  static wrap(client: ControlClient): SipClient {
    return new SipClient(client);
  }

  /** The underlying generic client (for raw `command` on any module). */
  get controlClient(): ControlClient {
    return this.client;
  }

  /** Register a call handler (does not block). */
  setCallHandler(handler: CallHandler): void {
    this.facade.setHandler(handler);
  }

  /**
   * Register a call handler **and drive the client to completion** (the
   * supervised reconnect + resync loop).
   */
  onCall(handler: CallHandler): Promise<void> {
    this.setCallHandler(handler);
    return this.client.run();
  }

  /** A pull-style stream of handed-over calls (alternative to a handler). */
  calls(): CallStream {
    return this.facade.setStream();
  }

  /** Drive the supervised connection loop (reconnect + resync). */
  run(): Promise<void> {
    return this.client.run();
  }

  /** Fetch the registered adapters' schema (`describe`). */
  describe(): Promise<unknown> {
    return this.client.describe();
  }

  /** Send a raw command on any module (the generic escape hatch). */
  command(
    module: string | null,
    verb: string,
    target: unknown,
    args: unknown,
  ): Promise<unknown> {
    return this.client.command(module, verb, target, args);
  }

  /** Stop the client. */
  shutdown(): void {
    this.client.shutdown();
  }
}

// ---------------------------------------------------------------------------
// Per-call-connect SIP facade
// ---------------------------------------------------------------------------

/** The SIP facade over a per-call-connect {@link ControlServer}. */
export class SipServer {
  private readonly facade = new SipFacade();

  private constructor(private readonly server: ControlServer) {
    server.onConnectionEvent((frame, transport) => this.facade.handleEvent(frame, transport));
  }

  /** Bind the listener and install the SIP event router. */
  static async bind(config: ServerConfig): Promise<SipServer> {
    const server = await ControlServerImpl.bind(config);
    return new SipServer(server);
  }

  /** The actual bound address (useful when binding to port 0 in tests). */
  localAddr(): import("node:net").AddressInfo {
    return this.server.localAddr();
  }

  /** Register a call handler (does not block). */
  setCallHandler(handler: CallHandler): void {
    this.facade.setHandler(handler);
  }

  /** A pull-style stream of dialed-in calls (alternative to a handler). */
  calls(): CallStream {
    return this.facade.setStream();
  }

  /** Register a call handler **and run the accept loop** to completion. */
  onCall(handler: CallHandler): Promise<void> {
    this.setCallHandler(handler);
    return this.server.run();
  }

  /** Accept siphon's per-call dials until the server is closed. */
  run(): Promise<void> {
    return this.server.run();
  }

  /** Stop accepting dials and close the listener. */
  close(): Promise<void> {
    return this.server.close();
  }
}
