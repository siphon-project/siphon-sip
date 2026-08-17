/**
 * Dispatch: a `StasisStart` event builds a `Call` and drives the registered
 * handler, in both connection modes — the inbound-persistent `SipClient.onCall`
 * and the per-call-connect `SipServer` where siphon dials in.
 */

import { describe, it, expect, afterEach } from "vitest";

import WebSocket from "ws";

import { SipClient, SipServer, SUBPROTOCOL } from "../src/index";
import type { Call } from "../src/index";
import { ControlStub, waitFor } from "./helpers";

interface ReplyLike {
  id: string;
  type: string;
  status?: string;
  verb?: string;
}
interface CommandLike {
  id: string;
  type: string;
  verb: string;
  target?: { channel?: string };
}

let cleanup: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  for (const step of cleanup.splice(0)) {
    await step();
  }
});

describe("inbound-persistent SipClient.onCall dispatch", () => {
  it("hands a StasisStart to the handler and drives call.answer()", async () => {
    const stub = await ControlStub.start({
      onCommand: (frame) =>
        frame.verb === "answer"
          ? { status: "ok", result: { state: "answered" } }
          : { status: "ok", result: {} },
    });
    cleanup.push(() => stub.stop());

    const sip = await SipClient.connect({ url: stub.url(), app: "ivr-app", token: "t" });

    let received: Call | undefined;
    const runPromise = sip.onCall(async (call) => {
      received = call;
      await call.answer();
    });

    await waitFor(() => stub.connectionCount() === 1);
    stub.pushEvent({
      event: "StasisStart",
      channel: "ch1",
      call_id: "call-uuid",
      sip_call_id: "sipcid@host",
      app: "ivr-app",
      payload: { source_ip: "203.0.113.7" },
    });

    await waitFor(() => received !== undefined);
    expect(received?.channelId).toBe("ch1");
    expect(received?.sipCallId).toBe("sipcid@host");
    expect(received?.callId).toBe("call-uuid");

    await waitFor(() =>
      stub.received.some((f) => f.verb === "answer" && f.target?.channel === "ch1"),
    );

    sip.shutdown();
    await runPromise;
  });
});

describe("per-call-connect SipServer dispatch (siphon dials in)", () => {
  it("accepts a dial, hands the StasisStart to the handler, and commands back", async () => {
    const server = await SipServer.bind({
      host: "127.0.0.1",
      port: 0,
      app: "ivr-app",
      token: "sekret",
    });
    cleanup.push(() => server.close());
    const port = server.localAddr().port;

    let received: Call | undefined;
    server.setCallHandler(async (call) => {
      received = call;
      await call.answer();
    });

    const dial = new WebSocket(`ws://127.0.0.1:${port}/`, [SUBPROTOCOL], {
      headers: { Authorization: "Bearer sekret" },
    });
    cleanup.push(() => dial.close());
    const inbound: ReplyLike[] = [];
    dial.on("message", (data) => inbound.push(JSON.parse(data.toString()) as CommandLike));

    await new Promise<void>((resolve, reject) => {
      dial.on("open", () => resolve());
      dial.on("error", reject);
    });

    // The first frame siphon sends on a per-call dial is StasisStart (no hello).
    dial.send(
      JSON.stringify({
        type: "event",
        event: "StasisStart",
        channel: "ch7",
        call_id: "cu-7",
        sip_call_id: "sc7@host",
        app: "ivr-app",
        payload: {},
      }),
    );

    await waitFor(() => received !== undefined);
    expect(received?.channelId).toBe("ch7");

    // The server (our SipServer) should have sent an answer command back to us.
    await waitFor(() => inbound.some((f) => f.type === "command" && (f as CommandLike).verb === "answer"));
    const answerCommand = inbound.find((f) => (f as CommandLike).verb === "answer") as CommandLike;
    expect(answerCommand.target?.channel).toBe("ch7");
    dial.send(JSON.stringify({ id: answerCommand.id, type: "reply", status: "ok", result: {} }));
  });
});
