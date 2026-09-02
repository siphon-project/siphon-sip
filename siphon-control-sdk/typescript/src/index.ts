/**
 * `@siphon-project/control` — the TypeScript client SDK for the SIPhon external control
 * plane (`siphon-control.v1`), an ARI/ESL-class rail for driving handed-over
 * calls out of process. The third client language alongside the Rust and Python
 * SDKs, over the byte-identical wire.
 *
 * ## Layering (protocol-agnostic core + typed facades)
 *
 * - {@link ControlClient} / {@link ControlServer} are the **generic core**:
 *   transport, `hello`, request-id correlation, reconnect + `resync`, and a
 *   generic event stream. Their headline primitive is
 *   {@link ControlClient.command}`(module, verb, target, args)`, which works for
 *   any adapter (`sip`, and future `smpp`/`ss7`) with zero changes.
 * - {@link SipClient} / {@link SipServer} are the **typed SIP facade**: a
 *   {@link Call}'s verbs (`answer`/`terminate`/`transfer`/…) are thin wrappers
 *   over `command("sip", …)`, and `StasisStart`→`Call` dispatch lives there.
 *
 * ```ts
 * import { SipClient } from "@siphon-project/control";
 *
 * const client = await SipClient.connect({
 *   url: "ws://siphon:9090/control/ws",
 *   app: "ivr-app",
 *   token: "s3cr3t",
 * });
 * await client.onCall(async (call) => {
 *   await call.answer();
 *   await call.transfer("sip:agent@pbx"); // REFER; awaits the correlated reply
 * });
 * ```
 *
 * ## Two connection modes
 *
 * - **Inbound-persistent** ({@link SipClient}): the app connects to siphon and
 *   keeps one long-lived socket (does `hello`).
 * - **Per-call-connect** ({@link SipServer}): siphon dials the app per
 *   handed-over call (the app is a WS server; no `hello`).
 *
 * ## Errors
 *
 * A `status:"error"` reply throws a {@link ControlError} carrying the stable
 * {@link ControlErrorCode} in `.code`. The WebSocket-tee verbs
 * ({@link Call.streamStart} / {@link Call.streamStop}) are siphon-rtp-only, so a
 * non-siphon-rtp backend throws `code === "unsupported_verb"`
 * (`error.isUnsupportedVerb()`).
 */

export { ControlError } from "./errors";
export type { ControlErrorCode, ControlErrorKind } from "./errors";

export {
  SUBPROTOCOL,
  PROTOCOL_VERSION,
  MODULE_SIP,
  MODULE_SMPP,
  MODULE_SS7,
  HELLO,
  RESYNC,
  DESCRIBE,
  SET_VAR,
  GET_VAR,
  SipVerb,
  sipEventKind,
  isTransferFinal,
  isBridgeFinal,
  encodeCommand,
  parseInboundFrame,
} from "./protocol";
export type {
  FrameType,
  ReplyStatus,
  ReplyError,
  ReplyFrame,
  EventFrame,
  HelloArgs,
  HelloResult,
  ChannelSnapshot,
  ResyncResult,
  SipVerbToken,
  SipEventKind,
  ChannelDtmfPayload,
  PlayStartedPayload,
  TransferReplaces,
  TransferRequestedPayload,
  TransferStage,
  TransferOutcomePayload,
  PeerHangupPolicy,
  BridgeRole,
  BridgeStage,
  ChannelBridgedPayload,
  BridgeFailedPayload,
  ChannelUnbridgedPayload,
  WsTeeStartedPayload,
  WsTeeEndedPayload,
  WsBridgeStartedPayload,
  WsBridgeEndedPayload,
} from "./protocol";

export { ControlClient, EventStream } from "./client";
export type { ClientConfig, ClientEvent } from "./client";

export { ControlServer } from "./server";
export type { ServerConfig, ConnectionEventSink } from "./server";

export type { CommandTransport, EventSink } from "./session";

export { Call, CallStream, SipClient, SipServer } from "./sip";
export type {
  CallEvent,
  CallHandler,
  ResponseOptions,
  ReferReplaces,
  AcceptReferOptions,
  BridgeOptions,
  RouteTarget,
  RouteTargetObject,
  PlaySource,
  PlayOptions,
  DtmfOptions,
  StreamOptions,
} from "./sip";
