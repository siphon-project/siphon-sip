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
  PeerHangupPolicy,
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
 * `TransferProgress`, `TransferCompleted`, `TransferFailed`, `ChannelBridged`,
 * `BridgeFailed`, `ChannelUnbridged`, `StasisEnd`, …).
 * Cast `payload` to
 * {@link import("./protocol").ChannelDtmfPayload} /
 * {@link import("./protocol").TransferRequestedPayload} /
 * {@link import("./protocol").TransferOutcomePayload} /
 * {@link import("./protocol").ChannelBridgedPayload} /
 * {@link import("./protocol").BridgeFailedPayload} /
 * {@link import("./protocol").ChannelUnbridgedPayload} by `kind`. */
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

/** Options for an anchored answer ({@link Call.answerAnchored}). */
export interface AnchoredAnswerOptions {
  /** UAS 2xx code (default `200`). */
  code?: number;
  /** Reason phrase (default `OK`). */
  reason?: string;
  /** Media profile to anchor with (default `voice_ai`). */
  profile?: string;
  /**
   * Per-call WebSocket bridge URI, overriding the profile's own. Supports
   * `{call_id}` / `{from_tag}` / `{from_user}` / `{to_user}` templating.
   */
  wsUri?: string;
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
  /**
   * Media profile for the pairing the transfer creates.
   *
   * **Required when the call is anchored with a direction-bound profile** — one
   * whose offer and answer halves describe different sides, such as
   * `srtp_to_rtp` at an SRTP edge. A transfer moves the party that half was
   * written for out of the call, so inheriting the profile re-offers *that
   * party's* transport to whoever remains: SRTP toward a plain-RTP carrier,
   * which answers `m=audio 0`. The call connects and carries no audio in either
   * direction while the SIP trace looks healthy.
   *
   * Pass the profile for the pair that remains (commonly `"rtp_passthrough"`).
   * Omitted inherits the call's profile, which is correct only when it is
   * symmetric.
   */
  profile?: string;
}

/** Options for {@link Call.bridge}. */
export interface BridgeOptions {
  /**
   * What happens to the surviving leg when its bridge partner hangs up —
   * `"hangup"` (the default) tears it down too, `"hold"` keeps it up, held and
   * still owned so it can be bridged to somebody else. See
   * {@link import("./protocol").PeerHangupPolicy}.
   */
  onPeerHangup?: PeerHangupPolicy;
}

/** A {@link Call.route} target carrying per-target overrides. */
export interface RouteTargetObject {
  /** The B-leg request URI to dial. */
  uri: string;
  /** Route egress to this next hop instead of resolving `uri`. */
  nextHop?: string;
  /** Headers injected on this attempt's B-leg INVITE. */
  headers?: Record<string, string>;
  /**
   * Per-target ring timeout in seconds. It bounds the wait for this carrier to
   * show progress (a 101-199), not the wait for its answer.
   */
  timeout?: number;
  /**
   * Fail this carrier over at its ring timeout even after it has shown
   * progress. By default a carrier that has sent a 180/183 keeps the call past
   * `timeout`, and the call then fails with 408 rather than trying the next
   * target; `true` is for a carrier that plays its own ringback before it has
   * reached anyone. Default `false`, which is never sent.
   */
  rerouteAfterProgress?: boolean;
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
  // Off is the server's default, so only `true` goes on the wire.
  if (target.rerouteAfterProgress === true) {
    object.reroute_after_progress = true;
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
/**
 * The media plan for {@link SipClient.originate} — what the outbound INVITE
 * offers.
 *
 * Required, and a union, because the server requires exactly one plan and
 * rejects every combination of the raw `sdp` / `body` / `media` arguments that
 * names none or more than one. Expressed this way those errors cannot be
 * written down.
 */
export type OriginateMedia =
  /** Offerless INVITE: siphon anchors the leg on the media engine. */
  | { anchor: true; profile?: string; wsUri?: string }
  /** Your own SDP offer (`application/sdp` by definition). */
  | { sdp: string }
  /** Your own body with its own content type. */
  | { body: string; contentType: string };

/**
 * Who refreshes each dialog of an originated call where the RFC 4028 negotiation
 * leaves siphon the choice (§7.1): the UAC of each dialog, the UAS of each, or
 * siphon on both.
 */
export type SessionRefresher = "uac" | "uas" | "b2bua";

/**
 * The RFC 4028 session timer siphon runs on an originated call, over its
 * `session_timer:` block. A field left out takes the server's default, as in the
 * script API's `call.session_timer()`: 1800 s, a `Min-SE` of 90 s, and `b2bua`.
 */
export interface SessionTimer {
  /** The session interval, in seconds. */
  expires?: number;
  /** The smallest session interval siphon accepts, in seconds. */
  minSe?: number;
  /** Who refreshes where the negotiation leaves siphon the choice. */
  refresher?: SessionRefresher;
}

/** Optional shaping for {@link SipClient.originate}. */
export interface OriginateOptions {
  /** From-URI to place the call as. */
  from?: string;
  /** From display name. */
  fromDisplay?: string;
  /** To display name. */
  toDisplay?: string;
  /** Route the INVITE here while keeping `to` as the R-URI. */
  nextHop?: string;
  /** P-Asserted-Identity to assert (RFC 3325). */
  pAssertedIdentity?: string;
  /** Caller-identity presentation (RFC 3323 §4.1). */
  privacy?: "allowed" | "restricted";
  /** Extra headers on the outbound INVITE. */
  headers?: Record<string, string>;
  /** Ring timeout in seconds. */
  timeout?: number;
  /** Control-loss policy for the created channel. */
  onLost?: string;
  /** Per-call variables carried on the channel. */
  vars?: Record<string, string>;
  /**
   * The RFC 4028 session timer to run on the call; left out, the one the server
   * has configured runs, if any.
   */
  sessionTimer?: SessionTimer;
}

/**
 * What the server answers an accepted `originate` with: the call is `calling`,
 * not answered — the answer arrives later as an event on the channel.
 */
export interface Originated {
  /** The caller-supplied channel id the call is addressed by. */
  channel: string;
  /** siphon's internal call id. */
  callId?: string;
  /** The SIP Call-ID on the wire, for joining CDR / HEP. */
  sipCallId?: string;
}

export function originateArgs(
  channel: string,
  to: string,
  media: OriginateMedia,
  options?: OriginateOptions,
): Record<string, unknown> {
  const args: Record<string, unknown> = { channel, to };
  if ("anchor" in media) {
    args.media = true;
    if (media.profile !== undefined) args.profile = media.profile;
    if (media.wsUri !== undefined) args.ws_uri = media.wsUri;
  } else if ("sdp" in media) {
    args.sdp = media.sdp;
  } else {
    args.body = media.body;
    args.content_type = media.contentType;
  }
  if (!options) return args;
  // Spelled out rather than looped: these are the exact wire names the server
  // parses, and a camelCase key would be silently ignored there — the call
  // still places, just without the identity or privacy that was asked for.
  if (options.from !== undefined) args.from = options.from;
  if (options.fromDisplay !== undefined) args.from_display = options.fromDisplay;
  if (options.toDisplay !== undefined) args.to_display = options.toDisplay;
  if (options.nextHop !== undefined) args.next_hop = options.nextHop;
  if (options.pAssertedIdentity !== undefined) {
    args.p_asserted_identity = options.pAssertedIdentity;
  }
  if (options.privacy !== undefined) args.privacy = options.privacy;
  if (options.headers !== undefined) args.headers = options.headers;
  if (options.timeout !== undefined) args.timeout = options.timeout;
  if (options.onLost !== undefined) args.on_lost = options.onLost;
  if (options.vars !== undefined) args.vars = options.vars;
  if (options.sessionTimer !== undefined) {
    const timer: Record<string, unknown> = {};
    const { expires, minSe, refresher } = options.sessionTimer;
    if (expires !== undefined) timer.expires = expires;
    if (minSe !== undefined) timer.min_se = minSe;
    if (refresher !== undefined) timer.refresher = refresher;
    args.session_timer = timer;
  }
  return args;
}

/**
 * One {@link Call.dial} target: a URI dialed as written, or an AoR forked to
 * every contact registered against it.
 *
 * Two shapes rather than a bare string, because the server accepts both and they
 * do entirely different things. A URI is dialed as written and resolved by DNS.
 * An AoR is resolved against the registrar and forked to *every* registered
 * contact, each branch over that contact's own captured flow — the only way to
 * reach a phone registered over TCP, TLS or WSS behind NAT, since such a contact
 * is reachable only on the connection it registered over.
 * `"sip:204@pbx.example"` is a plausible spelling of both, and the wrong one
 * places a call that connects to nothing while the trace looks healthy.
 */
export type DialTarget =
  | {
      /** The B-leg request URI, dialed as written. */
      uri: string;
      /** Send the INVITE here instead; the R-URI keeps `uri`'s shape. */
      nextHop?: string;
      /** Headers injected on this branch's INVITE, over the command's. */
      headers?: Record<string, string>;
    }
  | {
      /**
       * The address of record to fork to its registered contacts. It takes no
       * `nextHop`: each branch routes over its own binding's captured flow, so
       * there would be nothing for one to apply to.
       */
      aor: string;
      /** Headers injected on every branch the AoR expands to. */
      headers?: Record<string, string>;
    };

/**
 * Optional shaping for {@link Call.dial}; anything left out takes the server's
 * own default rather than a copy of it pinned here.
 */
export interface DialOptions {
  /** How to try the targets (`"parallel"` server-side when unset). */
  strategy?: "parallel" | "sequential";
  /** Ring timeout in seconds (30 server-side when unset, clamped to 1..3600). */
  timeout?: number;
  /** Headers injected on every branch's INVITE, under each target's own. */
  headers?: Record<string, string>;
  /**
   * A configured media profile to anchor both legs through, so the caller and
   * the phones never exchange media directly.
   *
   * What a carrier-delivered call to a ring group needs: the carrier hands over
   * plain RTP at a routable address and every phone answers from an address on
   * its own LAN, so without the relay in the middle the two ends cannot reach
   * each other. Left out, the caller's own SDP passes through.
   */
  profile?: string;
  /**
   * The calling identity to present — the From URI (RFC 3261 §8.1.1.3).
   *
   * Without it a B-leg presents the caller's own From, which on a call out to a
   * trunk is the internal extension. A carrier that looks its account up by the
   * From user does not recognise that, so it challenges the INVITE and keeps
   * challenging however correct the digest is. A `headers` entry cannot do
   * this: From is framework-managed on a B-leg and is rewritten after the fact.
   */
  from?: string;
  /**
   * The From display name. Naming a `from` without one drops the caller's
   * rather than presenting it beside a number that replaced it.
   */
  fromDisplay?: string;
  /**
   * `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1). Reaches the
   * wire after the header policy, so a preset that strips `P-*` at a trust
   * boundary cannot silently drop it.
   */
  pAssertedIdentity?: string;
  /**
   * Whether the calling identity may be presented (RFC 3323 §4.1 / TS 24.607).
   * `"restricted"` anonymises From and asserts `Privacy: id`, keeping the real
   * identity in `pAssertedIdentity` for the trusted next hop.
   */
  privacy?: "allowed" | "restricted";
}

/**
 * What the server answers an accepted `dial` with: the INVITEs are on the wire
 * and nobody has answered yet.
 */
export interface Dialing {
  /** The channel the targets are being rung for — still the caller's. */
  channel: string;
  /**
   * How many **branches** the server resolved, which an AoR expands: a single
   * AoR target registered on three devices reports three.
   */
  targets?: number;
  /** The strategy in force (the server's default when none was asked for). */
  strategy?: string;
  /** The ring timeout in force, in seconds. */
  timeout?: number;
}

/** Which side of the call {@link Call.recordStart} writes. */
export type RecordDirection = "ingress" | "egress" | "both";

/** The channel layout of the recorded file. */
export type RecordChannels = "mono" | "stereo";

/** Optional shaping for {@link Call.recordStart}. */
export interface RecordOptions {
  /** Which side to record (`"ingress"` server-side when unset). */
  direction?: RecordDirection;
  /** The file's channel layout (`"mono"` server-side when unset). */
  channels?: RecordChannels;
  /** Stop after this many milliseconds of recording. */
  maxDurationMs?: number;
  /** Stop after this many milliseconds of silence. */
  silenceMs?: number;
  /** Where the engine writes the file. */
  path?: string;
}

/** What the server answers an accepted `record_start` with. */
export interface Recording {
  /** The channel being recorded. */
  channel: string;
  /**
   * The id a later {@link Call.recordStop} and the `RecordingFinished` event
   * carry.
   */
  recordingId?: string;
}

function dialTargetToWire(target: DialTarget): unknown {
  const uri = (target as { uri?: unknown }).uri;
  const aor = (target as { aor?: unknown }).aor;
  const nextHop = (target as { nextHop?: unknown }).nextHop;
  const headers = (target as { headers?: Record<string, string> }).headers;
  if (typeof uri === "string" && typeof aor === "string") {
    throw new TypeError(
      'a dial target names "uri" or "aor", never both — siphon reads the aor ' +
        "and ignores the uri beside it, so this would place a different call",
    );
  }
  if (typeof aor === "string") {
    if (nextHop !== undefined) {
      throw new TypeError(
        'an aor target takes no "nextHop": each of its branches routes over ' +
          "its own contact's captured flow",
      );
    }
    const object: Record<string, unknown> = { aor };
    if (headers !== undefined) object.headers = headers;
    return object;
  }
  if (typeof uri !== "string") {
    throw new TypeError('a dial target requires a string "uri" or "aor"');
  }
  // A bare URI with no overrides is a plain string on the wire.
  if (nextHop === undefined && headers === undefined) return uri;
  const object: Record<string, unknown> = { uri };
  if (nextHop !== undefined) object.next_hop = nextHop;
  if (headers !== undefined) object.headers = headers;
  return object;
}

export function dialArgs(
  targets: DialTarget[],
  options?: DialOptions,
): Record<string, unknown> {
  const args: Record<string, unknown> = { targets: targets.map(dialTargetToWire) };
  if (!options) return args;
  if (options.strategy !== undefined) args.strategy = options.strategy;
  if (options.timeout !== undefined) args.timeout = options.timeout;
  if (options.headers !== undefined) args.headers = options.headers;
  if (options.profile !== undefined) args.profile = options.profile;
  if (options.from !== undefined) args.from = options.from;
  if (options.fromDisplay !== undefined) args.from_display = options.fromDisplay;
  if (options.pAssertedIdentity !== undefined) {
    args.p_asserted_identity = options.pAssertedIdentity;
  }
  if (options.privacy !== undefined) args.privacy = options.privacy;
  return args;
}

export function recordStartArgs(options?: RecordOptions): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  if (!options) return args;
  if (options.direction !== undefined) args.direction = options.direction;
  if (options.channels !== undefined) args.channels = options.channels;
  if (options.maxDurationMs !== undefined) args.max_duration_ms = options.maxDurationMs;
  if (options.silenceMs !== undefined) args.silence_ms = options.silenceMs;
  if (options.path !== undefined) args.path = options.path;
  return args;
}

export function recordStopArgs(recordingId?: string): Record<string, unknown> {
  // Absent, not null — which is what makes the server stop every recording on
  // the call rather than one named `null`.
  return recordingId === undefined ? {} : { recording_id: recordingId };
}

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

  /**
   * Answer the parked A-leg **and** anchor its media to the media engine in one
   * act — the verb form of the routing script's
   * `call.handover(answer=True, profile=…, ws_uri=…)`.
   *
   * This is how an application that accepted an **un-answered** handover
   * connects the call. It can already hold the call open for as long as its own
   * policy says with {@link Call.ring}; what it could not do is connect the
   * caller to anything, because a plain {@link Call.answer} sends a 2xx and
   * anchors nothing. Answering first and attaching a stream afterwards is not
   * the same thing: `received_from`, echo cancellation and the VAD engine are
   * properties of the answer, not of a bridge attached after it.
   *
   * Synthesizing the RFC 3264 answer against the media engine is a siphon-rtp
   * capability, so on rtpengine / rtpproxy this rejects with
   * `code === "unavailable"` rather than sending a 200 with nothing behind it.
   * On any media failure the 2xx is never sent and the call stays parked —
   * retry with another profile, or reject it.
   */
  async answerAnchored(options?: AnchoredAnswerOptions): Promise<void> {
    // `anchor` explicitly, rather than inferring it from `profile` being
    // present: with no options at all this still has to mean "answer through
    // the media engine on its default profile".
    const args: Record<string, unknown> = { anchor: true };
    if (options?.code !== undefined) {
      args.code = options.code;
    }
    if (options?.reason !== undefined) {
      args.reason = options.reason;
    }
    if (options?.profile !== undefined) {
      args.profile = options.profile;
    }
    if (options?.wsUri !== undefined) {
      args.ws_uri = options.wsUri;
    }
    await this.sip(SipVerb.Answer, args);
  }

  /**
   * Send `180 Ringing`: alerting only, no early media.
   *
   * RFC 3261 §13.2.1 makes the 180 the "callee is being alerted" signal, and
   * RFC 3960 §3.1 puts early media on a response that carries SDP — two
   * different acts, so two verbs. Ring for as long as your own policy says,
   * then {@link Call.answer}; open an early-media path with
   * {@link Call.progress}.
   */
  async ring(reason?: string): Promise<void> {
    await this.sip(SipVerb.Ring, reason !== undefined ? { reason } : {});
  }

  /**
   * Send a UAS 1xx, optionally opening an early-media path with SDP (default
   * `183 Session Progress`). For plain alerting use {@link Call.ring}.
   */
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

  /**
   * Send an in-dialog REFER on the A-leg (blind transfer).
   *
   * Resolves as soon as siphon has sent the REFER — that is *sent*, not
   * *transferred*. RFC 3515 §2.4.4 delivers the outcome afterwards on the
   * implicit subscription, so read it off {@link Call.events}: zero or more
   * `TransferProgress`, then exactly one `TransferCompleted` /
   * `TransferFailed`, each carrying a
   * {@link import("./protocol").TransferOutcomePayload}. Use
   * {@link import("./protocol").isTransferFinal} to know when to stop waiting.
   */
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
   * (`{uri, nextHop?, headers?, timeout?, rerouteAfterProgress?}`). A target
   * that has shown progress keeps the call past its `timeout` unless it sets
   * `rerouteAfterProgress`. `strategy` defaults to
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
   * Ring `targets` as B-legs while the caller stays **unanswered** and this
   * application keeps the channel.
   *
   * The difference from {@link Call.route} is who holds the call afterwards.
   * `route` hands it back to siphon, so the app gets `StasisEnd{reason: routed}`
   * and loses it; there is then no way to say "ring the extension, and if nobody
   * answers, voicemail" without answering the caller first — which starts
   * billing before anyone picks up, records an unanswered call as answered, and
   * denies the caller the callee's own ringback.
   *
   * The first 2xx answers the caller with the winner's SDP and the pair becomes
   * an ordinary two-leg call, still owned by this app. A failure or timeout
   * arrives as a `DialFailed` event with the caller still ringing and still
   * parked, so the app decides what happens next.
   *
   * Each target is a URI (dialed as written) or an `{aor}` (forked to every
   * registered contact over its own flow) — see {@link DialTarget}, and note
   * that a target naming both, or neither, throws before anything is sent.
   *
   * ```ts
   * const dialing = await call.dial(
   *   [{ aor: "sip:204@pbx.example" }],
   *   { strategy: "sequential", timeout: 20 },
   * );
   * ```
   *
   * Rejects with `code === "not_found"` (the call is gone, or no target yielded
   * a branch — an AoR nobody has registered), `"invalid_state"` (already
   * answered, which is what this verb exists to avoid), `"bad_request"` (an
   * empty or malformed target list) or `"unsupported_verb"` (a strategy siphon
   * does not implement).
   */
  async dial(targets: DialTarget[], options?: DialOptions): Promise<Dialing> {
    const result = (await this.sip(SipVerb.Dial, dialArgs(targets, options))) as
      | Record<string, unknown>
      | null;
    const text = (name: string): string | undefined => {
      const value = result?.[name];
      return typeof value === "string" ? value : undefined;
    };
    const count = (name: string): number | undefined => {
      const value = result?.[name];
      return typeof value === "number" ? value : undefined;
    };
    return {
      // The server echoes the channel back; fall back to the one addressed
      // rather than returning an empty id.
      channel: text("channel") ?? this.channelId,
      targets: count("targets"),
      strategy: text("strategy"),
      timeout: count("timeout"),
    };
  }

  /**
   * Accept a *pending inbound* REFER (surfaced as a `TransferRequested` event)
   * and run the transfer. `target` overrides the Refer-To URI, `nextHop` steers
   * egress, and `mode` (`"terminate"` / `"transparent"`) overrides
   * `b2bua.default_refer_mode`. No pending REFER (already decided, timed out, or
   * the call is gone) rejects with `code === "not_found"`.
   *
   * `profile` names the media profile for the pairing the transfer creates —
   * see {@link AcceptReferOptions.profile}, which is required at an SRTP edge.
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
    if (options?.profile !== undefined) {
      args.profile = options.profile;
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

  /**
   * Join this call to another leg the app owns, so the two parties hear each
   * other.
   *
   * **This call is the anchor.** It keeps its media session — its ports and
   * everything attached to them; the `withChannel` leg's own media session is
   * deleted and it becomes the second party on this one's. So bridge *into* the
   * leg whose media you want to keep (the one being recorded, teed, or carrying
   * the prompt).
   *
   * Both legs must already be answered. `options.onPeerHangup` says what happens
   * to the survivor when its partner hangs up (see
   * {@link import("./protocol").PeerHangupPolicy}); omitted means `"hangup"`.
   *
   * Resolves as soon as the media has been re-pointed and the first re-INVITE is
   * on the wire — that is *offered*, not *bridged*. A bridge is two RFC 3261 §14
   * re-INVITEs across two dialogs, so the outcome arrives on {@link Call.events}
   * instead: exactly one `ChannelBridged`
   * ({@link import("./protocol").ChannelBridgedPayload}) / `BridgeFailed`
   * ({@link import("./protocol").BridgeFailedPayload}), on **both** channels.
   * {@link import("./protocol").isBridgeFinal} says when to stop waiting.
   *
   * Resolves to the reply `result` (`{channel, with, call_id, peer_call_id,
   * anchored, on_peer_hangup, state: "bridging"}`). Rejects with a `code` a
   * caller can act on: `"not_found"` (no such leg), `"invalid_state"` (a leg has
   * not answered, is already bridged, has a re-INVITE outstanding, or carries no
   * media description), `"bad_request"` (the same leg named twice, or a bad
   * `onPeerHangup`), `"forbidden"` (the other channel belongs to another app),
   * `"unsupported_verb"` (the media backend cannot express it).
   */
  async bridge(withChannel: string, options?: BridgeOptions): Promise<unknown> {
    const args: Record<string, unknown> = { with: withChannel };
    if (options?.onPeerHangup !== undefined) {
      args.on_peer_hangup = options.onPeerHangup;
    }
    return this.sip(SipVerb.Bridge, args);
  }

  /**
   * Break this call's bridge.
   *
   * Both legs stay answered, owned and held — re-offered `a=sendonly`
   * (RFC 3264 §8.4, which RFC 6337 §3.1 prefers to `c=0.0.0.0`). Neither is hung
   * up: that would be indistinguishable from two hangups and would take away the
   * calls the app still owns. A later {@link Call.bridge} re-offers `sendrecv`.
   *
   * `reason` is free text carried on the `ChannelUnbridged`
   * ({@link import("./protocol").ChannelUnbridgedPayload}) event both channels
   * receive; omitted means `"unbridged"`. Resolves to the reply `result`
   * (`{channel, with, reason, state: "unbridged"}`), where `with` is the channel
   * id of the leg that was on the other side. A call that is not bridged rejects
   * with `code === "invalid_state"`.
   */
  async unbridge(reason?: string): Promise<unknown> {
    return this.sip(SipVerb.Unbridge, reason !== undefined ? { reason } : {});
  }

  /**
   * Replace one leg of this answered call with a freshly dialed target, with no
   * REFER involved.
   *
   * The transfer siphon already runs for a REFER it terminates, reachable
   * because *this app* decided: an IVR that has worked out where the caller
   * should go, a controller handing a call from an AI to a human, a supervisor
   * take-over. siphon dials `target` as a new leg on the same call, re-anchors
   * the surviving party's media onto it, and once the target answers promotes
   * it into the surviving pair and BYEs the leg it replaced.
   *
   * The replaced leg **stays up while the target rings**, so the surviving
   * party hears ringback rather than silence, and a target that refuses or
   * never answers leaves the call exactly as it was.
   *
   * `replaceALeg` picks the direction: omitted/`false` replaces the callee and
   * keeps the caller, `true` does the reverse. `profile` names the media
   * profile for the pair this creates — required when the call is anchored with
   * a direction-bound one, whose answer half describes the party that is
   * leaving. `timeout` bounds the ring in seconds (`0` = no ring policy, only
   * siphon's guard against a target that answers nothing).
   *
   * Resolves as soon as the INVITE is on the wire
   * (`{channel, replacement: "dialing", target}`) and says nothing about the
   * target. Wait for the `PeerReplaced`
   * ({@link import("./protocol").PeerReplacedPayload}) or `ReplaceFailed`
   * ({@link import("./protocol").ReplaceFailedPayload}) event for the outcome —
   * acting on the reply alone would tear down a call whose replacement is still
   * ringing.
   *
   * Rejects with `code === "not_found"` (no such call), `"invalid_state"` (not
   * answered, no peer leg, or a replacement already in flight — all worth
   * retrying later) or `"bad_request"` (the target will not parse or route).
   */
  async replacePeer(
    target: string,
    options: {
      nextHop?: string;
      replaceALeg?: boolean;
      profile?: string;
      timeout?: number;
    } = {},
  ): Promise<unknown> {
    const args: Record<string, unknown> = { target };
    if (options.nextHop !== undefined) args.next_hop = options.nextHop;
    if (options.replaceALeg !== undefined) args.replace_a_leg = options.replaceALeg;
    if (options.profile !== undefined) args.profile = options.profile;
    if (options.timeout !== undefined) args.timeout = options.timeout;
    return this.sip(SipVerb.ReplacePeer, args);
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

  /**
   * Record this call's decoded audio to a wav file.
   *
   * The reply names the `recordingId` a later {@link Call.recordStop}
   * addresses. It is **not** the file: `RecordingFinished` fires when the file
   * is *closed* and names its path, which is what an app that mails the audio
   * has to wait for — acting on this reply races a half-written file.
   *
   * `maxDurationMs` and `silenceMs` are the two stop conditions a voicemail
   * greeting announces, and the engine evaluates both where the decoded audio
   * already is. Not SIPREC: this writes a file and works on a single-leg,
   * engine-terminated call, which is what a voicemail box is. siphon-rtp
   * backend only — rtpengine / rtpproxy reject with
   * `code === "unsupported_verb"`; a call with no anchored media session
   * rejects with `"not_found"`.
   */
  async recordStart(options?: RecordOptions): Promise<Recording> {
    const result = (await this.sip(
      SipVerb.RecordStart,
      recordStartArgs(options),
    )) as Record<string, unknown> | null;
    const text = (name: string): string | undefined => {
      const value = result?.[name];
      return typeof value === "string" ? value : undefined;
    };
    return {
      channel: text("channel") ?? this.channelId,
      recordingId: text("recording_id"),
    };
  }

  /**
   * Stop the recording named by `recordingId`, or **every** recording on this
   * call when it is left out.
   *
   * Resolves once the engine has accepted the stop; the file is not closed yet.
   * `RecordingFinished` says that, and carries the path and the reason
   * (`stopped`, `max_duration`, `silence`, `call_ended`, `error`).
   */
  async recordStop(recordingId?: string): Promise<void> {
    await this.sip(SipVerb.RecordStop, recordStopArgs(recordingId));
  }

  // --- escape hatch + events --------------------------------------------

  /** Send an arbitrary SIP-adapter verb + args and return the raw result. */
  async command(verb: string, args?: unknown): Promise<unknown> {
    return this.sip(verb, args ?? {});
  }

  /**
   * Await the next event for this call (`ChannelStateChange`,
   * `ChannelHangupRequest`, `ChannelBridged`, `BridgeFailed`,
   * `ChannelUnbridged`, `StasisEnd`). `null` once the stream closes.
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

  /**
   * Place an outbound call under a caller-supplied channel id.
   *
   * The one verb that *creates* a channel rather than addressing one, which is
   * why it lives here and not on {@link Call}. It resolves as soon as the
   * INVITE is on the wire — the call is `calling`, and the answer, failure or
   * timeout arrives later as an event on the channel.
   *
   * ```ts
   * const call = await client.originate(
   *   "wake-up-42",
   *   "sip:1001@pbx.example",
   *   { anchor: true },
   *   { from: "sip:alarm@pbx.example", timeout: 20 },
   * );
   * ```
   */
  async originate(
    channel: string,
    to: string,
    media: OriginateMedia,
    options?: OriginateOptions,
  ): Promise<Originated> {
    const result = (await this.client.command(
      MODULE_SIP,
      "originate",
      null,
      originateArgs(channel, to, media, options),
    )) as Record<string, unknown> | null;
    const text = (name: string): string | undefined => {
      const value = result?.[name];
      return typeof value === "string" ? value : undefined;
    };
    return {
      // The server echoes the id back; fall back to the one we asked for
      // rather than returning an empty channel a caller cannot address.
      channel: text("channel") ?? channel,
      callId: text("call_id"),
      sipCallId: text("sip_call_id"),
    };
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
