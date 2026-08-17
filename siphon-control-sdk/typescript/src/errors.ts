/**
 * The client error type for the SIPhon control plane.
 *
 * The load-bearing case is a server `status:"error"` reply, which becomes a
 * {@link ControlError} carrying the stable {@link ControlErrorCode} in `.code`
 * so callers can branch on the cause (e.g. treat `unsupported_verb` as "the
 * server doesn't do media yet" rather than a hard failure). Mirrors the Rust
 * `ControlError` enum and the Python `ControlError` exception.
 */

/** Stable machine-readable error codes returned in a reply's `error.code`. */
export type ControlErrorCode =
  | "unauthorized"
  | "forbidden"
  | "not_found"
  | "bad_request"
  | "rate_limited"
  | "originate_denied"
  | "unsupported_verb"
  | "unsupported_version"
  | "protocol_error"
  | "unavailable";

/**
 * How a {@link ControlError} arose. `command` is the wire-level rejection (it
 * carries a {@link ControlErrorCode}); the rest are transport / local failures
 * that never had a wire code.
 */
export type ControlErrorKind =
  | "command"
  | "unauthorized"
  | "handshake"
  | "closed"
  | "timeout"
  | "websocket"
  | "config";

/** Everything that can go wrong driving the control plane. */
export class ControlError extends Error {
  /** The classification of this error. */
  readonly kind: ControlErrorKind;
  /** The stable wire code, present only for a `command` rejection. */
  readonly code?: ControlErrorCode;
  /** The HTTP status of a rejected upgrade, present only for `unauthorized`. */
  readonly status?: number;

  constructor(
    kind: ControlErrorKind,
    message: string,
    options?: { code?: ControlErrorCode; status?: number },
  ) {
    super(message);
    this.name = "ControlError";
    this.kind = kind;
    this.code = options?.code;
    this.status = options?.status;
    // Restore the prototype chain across the transpiled `extends Error`.
    Object.setPrototypeOf(this, ControlError.prototype);
  }

  /**
   * True when this is a server-side `unsupported_verb` rejection — the state a
   * media verb (`playFile`/`dtmf`/…) lands in until the server implements it.
   */
  isUnsupportedVerb(): boolean {
    return this.kind === "command" && this.code === "unsupported_verb";
  }

  /** A server `status:"error"` reply. */
  static command(code: ControlErrorCode, message: string): ControlError {
    return new ControlError("command", `control command rejected (${code}): ${message}`, {
      code,
    });
  }

  /** The WebSocket upgrade was rejected before it opened (bad/missing token). */
  static unauthorized(status: number): ControlError {
    return new ControlError(
      "unauthorized",
      `unauthorized: the control token was rejected (HTTP ${status})`,
      { status },
    );
  }

  /** The `hello` handshake (or subprotocol negotiation) failed. */
  static handshake(detail: string): ControlError {
    return new ControlError("handshake", `handshake failed: ${detail}`);
  }

  /** The connection is closed (or was never established). */
  static closed(): ControlError {
    return new ControlError("closed", "control connection is closed");
  }

  /** A command was sent but no reply arrived within the configured window. */
  static timeout(timeoutMs: number): ControlError {
    return new ControlError("timeout", `timed out awaiting a reply after ${timeoutMs}ms`);
  }

  /** A transport-level WebSocket error. */
  static websocket(detail: string): ControlError {
    return new ControlError("websocket", `websocket error: ${detail}`);
  }

  /** A configuration value was invalid (bad URL, bad listen address, …). */
  static config(detail: string): ControlError {
    return new ControlError("config", `configuration error: ${detail}`);
  }
}
