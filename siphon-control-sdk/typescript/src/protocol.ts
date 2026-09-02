/**
 * Wire protocol for the SIPhon external control plane (`siphon-control.v1`).
 *
 * This module is the TypeScript mirror of the Rust `siphon-control-proto` crate
 * and the server's inline `src/control/protocol.rs`. The frame shapes here are
 * **byte-identical** to what the server emits and parses:
 *
 * - **command** (client → siphon): `{id, type:"command", module?, verb, target, args}`
 * - **reply** (siphon → client, `id` echoed): `{id, type:"reply", status, result|error}`
 * - **event** (siphon → client, un-id'd, pushed): `{type:"event", event, channel?, app?, call_id?, sip_call_id?, payload?}`
 *
 * `module` routes a command to the registered adapter (`sip`|`smpp`|`ss7`);
 * substrate verbs (`hello`, `resync`, `describe`, `set_var`, `get_var`) omit it.
 */

/** The WebSocket subprotocol token this rail speaks. */
export const SUBPROTOCOL = "siphon-control.v1";

/** The protocol version this build implements. */
export const PROTOCOL_VERSION = 1;

/** Adapter routing key for the built-in SIP adapter. */
export const MODULE_SIP = "sip";
/** Adapter routing key for an SMPP adapter (registered by a host binary). */
export const MODULE_SMPP = "smpp";
/** Adapter routing key for an SS7 adapter (registered by a host binary). */
export const MODULE_SS7 = "ss7";

/** The mandatory first-frame handshake verb. */
export const HELLO = "hello";
/** Substrate verb: re-enumerate the channels this connection owns. */
export const RESYNC = "resync";
/** Substrate verb: fetch the registered adapters' schema. */
export const DESCRIBE = "describe";
/** Substrate verb: set a per-channel variable. */
export const SET_VAR = "set_var";
/** Substrate verb: read a per-channel variable. */
export const GET_VAR = "get_var";

/** The `type` discriminator on every frame. */
export type FrameType = "command" | "reply" | "event";

/** The status of a reply. */
export type ReplyStatus = "ok" | "error";

import type { ControlErrorCode } from "./errors";

/** The error body of a failed reply. */
export interface ReplyError {
  code: ControlErrorCode;
  message: string;
}

/** A reply frame (siphon → client, `id` echoed). */
export interface ReplyFrame {
  id: string;
  type: "reply";
  status: ReplyStatus;
  /** Present on success. */
  result?: unknown;
  /** Present on failure. */
  error?: ReplyError;
}

/**
 * A pushed event frame (siphon → client, un-id'd).
 *
 * Carries the stable id triple `{channel, call_id, sip_call_id}` so a controller
 * joins CDR + HEP with no mapping table: `sip_call_id` is byte-identical to the
 * CDR `call_id` and the HEP correlation chunk.
 */
export interface EventFrame {
  type: "event";
  /** Event name (e.g. `"StasisStart"`, `"StasisEnd"`). */
  event: string;
  /** The channel this event concerns (leg-scoped id), when applicable. */
  channel?: string;
  /** The application the channel was handed to. */
  app?: string;
  /** The internal call UUID (`CallActor.id`) — the grouping key across legs. */
  call_id?: string;
  /** The per-leg SIP Call-ID — the CDR / HEP join key. */
  sip_call_id?: string;
  /** Event-specific payload. */
  payload?: unknown;
}

/** Arguments of the `hello` handshake command. */
export interface HelloArgs {
  app: string;
  protocol?: number;
}

/** The `result` of a successful `hello` reply. */
export interface HelloResult {
  app: string;
  protocol: number;
  subprotocol: string;
}

/** One channel in a `resync` reply — the id triple plus its state + vars. */
export interface ChannelSnapshot {
  channel: string;
  call_id: string;
  sip_call_id: string;
  state: string;
  vars: Record<string, string>;
}

/** The `result` of a successful `resync` reply. */
export interface ResyncResult {
  channels: ChannelSnapshot[];
}

/**
 * Serialize a command frame to the exact JSON bytes the server parses.
 *
 * Field order follows the server's struct declaration order — `id`, `type`,
 * `module` (omitted when absent), `verb`, `target`, `args` — so the bytes are
 * identical to the Rust `CommandFrame` serialization. `target`/`args` are always
 * emitted (defaulting to JSON `null`); `module` is dropped when null/undefined.
 */
export function encodeCommand(
  id: string,
  module: string | null | undefined,
  verb: string,
  target: unknown,
  args: unknown,
): string {
  const frame: Record<string, unknown> = { id, type: "command" };
  if (module != null) {
    frame.module = module;
  }
  frame.verb = verb;
  frame.target = target ?? null;
  frame.args = args ?? null;
  return JSON.stringify(frame);
}

/** Parse an inbound text frame into a {@link ReplyFrame} or {@link EventFrame}. */
export function parseInboundFrame(text: string): ReplyFrame | EventFrame | null {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return null;
  }
  if (typeof value !== "object" || value === null) {
    return null;
  }
  const frameType = (value as { type?: unknown }).type;
  if (frameType === "reply") {
    return value as ReplyFrame;
  }
  if (frameType === "event") {
    return value as EventFrame;
  }
  return null;
}

// ---------------------------------------------------------------------------
// SIP adapter (`module = "sip"`) verb + event helper names.
// ---------------------------------------------------------------------------

/**
 * The verbs the built-in SIP adapter accepts (`module = "sip"`).
 *
 * These are the exact wire tokens. The media verbs
 * (`play`/`stop`/`dtmf`/`hold`/`unhold`/`stream_start`/`stream_stop`) dispatch
 * against the configured media backend; the WebSocket-tee pair is
 * siphon-rtp-only, so a non-siphon-rtp backend answers them `unsupported_verb`.
 */
export const SipVerb = {
  Answer: "answer",
  /**
   * `180 Ringing` — alerting only, no early media (RFC 3261 §13.2.1). A body is
   * refused: SDP on an 18x is early media (RFC 3960 §3.1), which is
   * {@link SipVerb.Progress}'s job.
   */
  Ring: "ring",
  Progress: "progress",
  Reject: "reject",
  Hangup: "hangup",
  Refer: "refer",
  Route: "route",
  SetHeader: "set_header",
  GetHeader: "get_header",
  RemoveHeader: "remove_header",
  AcceptRefer: "accept_refer",
  RejectRefer: "reject_refer",
  Bridge: "bridge",
  Unbridge: "unbridge",
  Play: "play",
  Stop: "stop",
  Dtmf: "dtmf",
  Hold: "hold",
  Unhold: "unhold",
  StreamStart: "stream_start",
  StreamStop: "stream_stop",
} as const;

/** A value of {@link SipVerb}. */
export type SipVerbToken = (typeof SipVerb)[keyof typeof SipVerb];

/** The well-known SIP-adapter event names (the ARI *Stasis* model). */
export type SipEventKind =
  | "StasisStart"
  | "StasisEnd"
  | "ChannelStateChange"
  | "ChannelHangupRequest"
  | "ChannelDtmfReceived"
  | "PlayStarted"
  | "TransferRequested"
  | "TransferProgress"
  | "TransferCompleted"
  | "TransferFailed"
  | "ChannelBridged"
  | "BridgeFailed"
  | "ChannelUnbridged"
  | "WsTeeStarted"
  | "WsTeeEnded"
  | "WsBridgeStarted"
  | "WsBridgeEnded"
  | (string & {});

/** Parse a wire event name; unknown names pass through verbatim (forward-compatible). */
export function sipEventKind(name: string): SipEventKind {
  return name as SipEventKind;
}

/**
 * The `payload` of a `ChannelDtmfReceived` event — an in-band DTMF digit the
 * media engine detected on a controlled call's leg. Cast a
 * {@link import("./sip").CallEvent}'s `payload` to this when
 * `kind === "ChannelDtmfReceived"`.
 */
export interface ChannelDtmfPayload {
  /** The single detected digit (`0`–`9`, `*`, `#`, `A`–`D`). */
  digit: string;
  /** The tone duration in milliseconds. */
  duration_ms: number;
  /** The tone volume in dBm0 (negative). */
  volume: number;
  /** The From-tag of the leg the digit came from. */
  from_tag: string;
}

/**
 * The `payload` of a `PlayStarted` event — a `play` the media backend accepted
 * and started. Cast a {@link import("./sip").CallEvent}'s `payload` to this when
 * `kind === "PlayStarted"`.
 *
 * `play_id` is the engine's handle on that one playback — what a targeted `stop`
 * ends and what a gain change addresses — and is the same value the `play`
 * command reply carried, which is how the event correlates with the command.
 * The media contract answers `play` accept-on-start, so this event is the
 * playback beginning, not a claim that audio has reached the wire: a fetched
 * source (`source: "url"`) accepts before its body has arrived, which is why
 * `duration_ms` can be absent.
 */
export interface PlayStartedPayload {
  /** Which source it started from: `file`, `blob`, `db_id`, `tone` or `url`. */
  source: string;
  /** The engine's handle on this playback, when it assigned one. */
  play_id?: number | null;
  /** The playback's length in ms, when the engine knew it at accept time. */
  duration_ms?: number | null;
}

/** The RFC 3891 `Replaces` triple embedded in a {@link TransferRequestedPayload}. */
export interface TransferReplaces {
  call_id: string;
  from_tag: string;
  to_tag: string;
  early_only: boolean;
}

/**
 * The `payload` of a `TransferRequested` event — an inbound REFER on a
 * controlled call, handed to the app to accept / reject. Cast a
 * {@link import("./sip").CallEvent}'s `payload` to this when
 * `kind === "TransferRequested"`.
 */
export interface TransferRequestedPayload {
  /** The Refer-To URI (the transfer target). */
  refer_to: string;
  /** The embedded `Replaces` triple for an attended transfer, if present. */
  replaces?: TransferReplaces | null;
  /** The From-tag of the referring party, if known. */
  from_tag?: string | null;
}

/**
 * Where a verdict on an *outbound* REFER came from — the `stage` of a
 * {@link TransferOutcomePayload}. Unknown tokens pass through verbatim
 * (forward-compatible).
 */
export type TransferStage =
  /** `2xx` to the REFER: accepted for processing only (RFC 3515 §2.4.4). */
  | "accepted"
  /** `401`/`407` answered with credentials; `attempt` says which try. */
  | "challenged"
  /** A non-terminating `message/sipfrag` NOTIFY reported progress. */
  | "notify"
  /** A terminating sipfrag NOTIFY reported a `2xx`: the transfer completed. */
  | "transferred"
  /** A terminating sipfrag NOTIFY reported `3xx`+: the target failed. */
  | "refused"
  /** The referee refused the REFER itself: the transfer never started. */
  | "rejected"
  /** Challenged with no way to answer (no credentials / retry cap). */
  | "unauthorized"
  /** The subscription ended with no usable status — never read as success. */
  | "no_outcome"
  /** The call ended with the transfer still outstanding. */
  | "call_ended"
  | (string & {});

/**
 * The `payload` shared by the `TransferProgress`, `TransferCompleted` and
 * `TransferFailed` events — one verdict on a transfer this app asked for with
 * the `refer` verb.
 *
 * The `refer` command resolves as soon as siphon has sent the REFER; RFC 3515
 * §2.4.4 puts the real outcome on the implicit subscription that follows. Expect
 * zero or more `TransferProgress`, then exactly one `TransferCompleted` /
 * `TransferFailed`. Cast a {@link import("./sip").CallEvent}'s `payload` to this
 * when `kind` is one of those three.
 */
export interface TransferOutcomePayload {
  /** Where this verdict came from. */
  stage: TransferStage;
  /** The Refer-To URI the REFER carried, when known. */
  refer_to?: string | null;
  /**
   * The SIP status this verdict rests on: the REFER's own response status for
   * `accepted` / `challenged` / `rejected` / `unauthorized`, the sipfrag status
   * for the NOTIFY-driven stages.
   */
  code?: number | null;
  /** That status's reason phrase, when the peer supplied one. */
  reason?: string | null;
  /**
   * Which REFER attempt this verdict is about, 1-based. `null` once the REFER
   * transaction is over (the NOTIFY-driven stages).
   */
  attempt?: number | null;
}

/**
 * Whether an event name ends a transfer this app asked for. Exactly one such
 * event arrives per `refer`, so this is the signal to stop waiting.
 */
export function isTransferFinal(name: string): boolean {
  return name === "TransferCompleted" || name === "TransferFailed";
}

/**
 * What happens to the surviving leg when its bridge partner hangs up — the
 * `onPeerHangup` option of {@link import("./sip").Call.bridge}.
 *
 * `"hangup"` (the default) tears the survivor down too: a bridged pair behaves
 * like one call. `"hold"` keeps it up, held (RFC 3264 §8.4) and still owned, so
 * the app can bridge it to somebody else — the supervisor / attended-hand-off
 * case. A closed set: the server refuses anything else with
 * `code === "bad_request"` rather than guessing at a teardown policy.
 */
export type PeerHangupPolicy = "hangup" | "hold";

/**
 * Which side of a bridge a leg is — the `role` of a
 * {@link ChannelBridgedPayload}. The `anchor` is the channel the `bridge` was
 * addressed to and keeps its media session; the `peer` is the one named by
 * `with`, whose own media session was deleted when it joined. Unknown tokens
 * pass through verbatim (forward-compatible).
 */
export type BridgeRole = "anchor" | "peer" | (string & {});

/**
 * Which of a bridge's two re-INVITEs was refused — the `stage` of a
 * {@link BridgeFailedPayload}. `offering_peer` means the `with` leg refused the
 * anchor's media and the anchor was never touched; `offering_anchor` means the
 * peer answered but the anchor refused what it was re-offered. Unknown tokens
 * pass through verbatim (forward-compatible).
 */
export type BridgeStage = "offering_peer" | "offering_anchor" | (string & {});

/**
 * The `payload` of a `ChannelBridged` event — the bridge formed and the two
 * parties can hear each other.
 *
 * A bridge is two RFC 3261 §14 re-INVITEs across two dialogs, so the `bridge`
 * command reply reports only the local action (the media re-pointed, the first
 * re-INVITE on the wire) and this event is the outcome. It is pushed on **both**
 * bridged channels, each copy naming the other leg. Cast a
 * {@link import("./sip").CallEvent}'s `payload` to this when
 * `kind === "ChannelBridged"`.
 */
export interface ChannelBridgedPayload {
  /** The internal `CallActor` id of the leg on the other side. */
  peer_call_id: string;
  /** That leg's SIP `Call-ID` — the CDR / HEP join key for the other party. */
  peer_sip_call_id: string;
  /** Which side *this* channel is. */
  role: BridgeRole;
  /** Whether the bridged pair lives on the media engine (the anchor's session). */
  anchored: boolean;
}

/**
 * The `payload` of a `BridgeFailed` event — one of the bridge's two re-INVITEs
 * was refused and both legs were left exactly as they were. Never a teardown:
 * the app still owns both calls and can retry, bridge elsewhere, or hang up.
 */
export interface BridgeFailedPayload {
  /** Which re-INVITE was refused. */
  stage: BridgeStage;
  /** The SIP status the refusing leg answered with (`488`, `491`, `500`, …). */
  code?: number | null;
  /** The SIP `Call-ID` of the other leg in the attempt. */
  peer_sip_call_id?: string | null;
}

/**
 * The `payload` of a `ChannelUnbridged` event — the bridge was broken. Both legs
 * stay answered, owned and held (RFC 3264 §8.4 `a=sendonly`); neither is hung
 * up, because that would be indistinguishable from two hangups. Pushed on both
 * channels.
 */
export interface ChannelUnbridgedPayload {
  /** The internal `CallActor` id of the leg that was on the other side. */
  peer_call_id: string;
  /** That leg's SIP `Call-ID`. */
  peer_sip_call_id: string;
  /** The reason the `unbridge` carried (default `"unbridged"`). */
  reason: string;
}

/**
 * The `payload` of a `WsTeeStarted` event — a WebSocket audio **tee** began
 * streaming a copy of the channel's audio. Additive: the call relays on
 * regardless, so a tee never affects the parties.
 *
 * `streamId` correlates this event with the `start` frame on the socket, and
 * the wire shape is stated so a consumer decodes the binary frames without
 * guessing.
 */
export interface WsTeeStartedPayload {
  from_tag: string;
  stream_id: string;
  ws_uri: string;
  /** `both`, `caller` or `callee`. */
  direction: string;
  /** 1 = mono/mixed, 2 = caller/callee interleaved. */
  channels: number;
  /** Wire sample rate in Hz (L16, little-endian). */
  sample_rate: number;
}

/**
 * The `payload` of a `WsTeeEnded` event. Exactly one arrives per
 * `WsTeeStarted`, including when the *server* ends it, so a consumer learns
 * the stream died rather than silently losing the audio.
 *
 * `frames_dropped > 0` means the consumer could not keep up; the call itself
 * was never affected.
 */
export interface WsTeeEndedPayload {
  from_tag: string;
  stream_id: string;
  /** `detached`, `server_closed`, `server_stopped`, `call_ended` or `transport_error`. */
  reason: string;
  /** `detached` is the only orderly end; anything else stopped the audio mid-call. */
  unexpected: boolean;
  frames_sent?: number | null;
  frames_dropped?: number | null;
}

/**
 * The `payload` of a `WsBridgeStarted` event — a WebSocket **takeover** bridge
 * began. Unlike a tee this *replaced* the call's audio path: the WebSocket
 * server is now the leg's far side and A-to-B is unwired.
 */
export interface WsBridgeStartedPayload {
  from_tag: string;
  stream_id: string;
  ws_uri: string;
  /** Wire sample rate in Hz (L16, little-endian). */
  sample_rate: number;
}

/**
 * The `payload` of a `WsBridgeEnded` event. Exactly one per
 * `WsBridgeStarted`; a re-point arrives as an ended (reason `detached`)
 * followed by a fresh started.
 *
 * `unexpected` matters more here than on a tee: a bridge *is* the call's media
 * path, so anything but `detached` leaves both parties up and hearing nothing.
 */
export interface WsBridgeEndedPayload {
  from_tag: string;
  stream_id: string;
  /** `detached`, `server_closed`, `server_stopped`, `call_ended` or `transport_error`. */
  reason: string;
  unexpected: boolean;
}

/**
 * Whether an event name ends a bridge this app asked for. Exactly one such event
 * arrives per `bridge`, so this is the signal to stop waiting. `ChannelUnbridged`
 * is not one of them — it ends a bridge that already formed.
 */
export function isBridgeFinal(name: string): boolean {
  return name === "ChannelBridged" || name === "BridgeFailed";
}
