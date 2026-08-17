/**
 * Correlation: a command sent over a live socket resolves with the matching
 * reply's `result`, a `status:"error"` reply throws a typed `ControlError` with
 * the wire `.code` (asserting `unsupported_verb`), and a dropped reply times out.
 */

import { describe, it, expect, afterEach } from "vitest";

import { ControlClient, ControlError } from "../src/index";
import { ControlStub } from "./helpers";

let stub: ControlStub | undefined;

afterEach(async () => {
  await stub?.stop();
  stub = undefined;
});

describe("request/reply correlation over a live socket", () => {
  it("resolves a command with the reply result and rejects unsupported_verb", async () => {
    stub = await ControlStub.start({
      onCommand: (frame) => {
        if (frame.verb === "answer") {
          return { status: "ok", result: { state: "answered", code: 200 } };
        }
        if (frame.verb === "play") {
          return { status: "error", error: { code: "unsupported_verb", message: "no media backend" } };
        }
        return { status: "ok", result: {} };
      },
    });

    const client = await ControlClient.connect({ url: stub.url(), app: "ivr-app", token: "t" });

    const ok = await client.command("sip", "answer", { channel: "ch1" }, {});
    expect(ok).toEqual({ state: "answered", code: 200 });

    let caught: unknown;
    try {
      await client.command("sip", "play", { channel: "ch1" }, { file: "x.wav" });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(ControlError);
    const controlError = caught as ControlError;
    expect(controlError.code).toBe("unsupported_verb");
    expect(controlError.kind).toBe("command");
    expect(controlError.isUnsupportedVerb()).toBe(true);

    client.shutdown();
  });

  it("times out when no reply arrives within the window", async () => {
    stub = await ControlStub.start({
      onCommand: (frame) => (frame.verb === "slow" ? undefined : { status: "ok", result: {} }),
    });

    const client = await ControlClient.connect({
      url: stub.url(),
      app: "ivr-app",
      token: "t",
      replyTimeoutMs: 120,
    });

    await expect(
      client.command("sip", "slow", { channel: "ch1" }, {}),
    ).rejects.toMatchObject({ kind: "timeout" });

    client.shutdown();
  });

  it("surfaces a rejected upgrade as an unauthorized error", async () => {
    stub = await ControlStub.start({ token: "right-token" });
    await expect(
      ControlClient.connect({ url: stub.url(), app: "ivr-app", token: "wrong-token" }),
    ).rejects.toMatchObject({ kind: "unauthorized" });
  });
});
