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
 * These are the exact wire tokens. The Phase-1 server implements
 * `answer`/`progress`/`reject`/`hangup`/`refer`/`set_header`/`get_header`;
 * the rest (`remove_header`, `accept_refer`, `reject_refer`, `play`, `dtmf`)
 * are accepted names the server answers `unsupported_verb` until it implements
 * them.
 */
export const SipVerb = {
  Answer: "answer",
  Progress: "progress",
  Reject: "reject",
  Hangup: "hangup",
  Refer: "refer",
  SetHeader: "set_header",
  GetHeader: "get_header",
  RemoveHeader: "remove_header",
  AcceptRefer: "accept_refer",
  RejectRefer: "reject_refer",
  Play: "play",
  Dtmf: "dtmf",
} as const;

/** A value of {@link SipVerb}. */
export type SipVerbToken = (typeof SipVerb)[keyof typeof SipVerb];

/** The well-known SIP-adapter event names (the ARI *Stasis* model). */
export type SipEventKind =
  | "StasisStart"
  | "StasisEnd"
  | "ChannelStateChange"
  | "ChannelHangupRequest"
  | (string & {});

/** Parse a wire event name; unknown names pass through verbatim (forward-compatible). */
export function sipEventKind(name: string): SipEventKind {
  return name as SipEventKind;
}
