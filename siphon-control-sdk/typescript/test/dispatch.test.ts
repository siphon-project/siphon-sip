/**
 * Dispatch: a `StasisStart` event builds a `Call` and drives the registered
 * handler, in both connection modes — the inbound-persistent `SipClient.onCall`
 * and the per-call-connect `SipServer` where siphon dials in.
 */

import { describe, it, expect, afterEach } from "vitest";

import WebSocket from "ws";

import { SipClient, SipServer, SUBPROTOCOL } from "../src/index";
import type {
  AppEvent,
  Call,
  DialogStateChangedPayload,
  RegistrationChangedPayload,
} from "../src/index";
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

describe("application-level events on SipClient", () => {
  it("hands a channel-less DialogStateChanged to onAppEvent, never to a call", async () => {
    const stub = await ControlStub.start();
    cleanup.push(() => stub.stop());
    const sip = await SipClient.connect({ url: stub.url(), app: "presence", token: "t" });

    const events: AppEvent[] = [];
    sip.onAppEvent((event) => events.push(event));
    let calls = 0;
    const runPromise = sip.onCall(() => {
      calls += 1;
    });

    await waitFor(() => stub.connectionCount() === 1);
    stub.pushEvent({
      event: "DialogStateChanged",
      app: "presence",
      payload: {
        aor: "sip:201@example.com",
        state: "confirmed",
        direction: "recipient",
        leg_id: "leg-1",
        call_id: "b1@host",
        local_tag: "phone-tag",
        remote_tag: "server-tag",
        remote_identity: { uri: "sip:15550100042@example.com", display_name: null },
      },
    });

    await waitFor(() => events.length === 1);
    expect(events[0]?.kind).toBe("DialogStateChanged");
    const payload = events[0]?.payload as DialogStateChangedPayload;
    expect(payload.aor).toBe("sip:201@example.com");
    expect(payload.state).toBe("confirmed");
    expect(payload.remote_identity.display_name).toBeNull();
    expect(calls).toBe(0);

    sip.shutdown();
    await runPromise;
  });
});

describe("registration state on SipClient", () => {
  it("types a RegistrationChanged and reads both state verbs", async () => {
    const stub = await ControlStub.start({
      onCommand: (frame) => {
        if (frame.verb === "registrations" && !frame.args?.after) {
          return {
            status: "ok",
            result: {
              seq: 41,
              next: "sip:200@example.com",
              registrations: [{ aor: "sip:200@example.com", contacts: [] }],
            },
          };
        }
        if (frame.verb === "registrations") {
          return {
            status: "ok",
            result: {
              seq: 45,
              next: null,
              registrations: [
                {
                  aor: "sip:201@example.com",
                  contacts: [
                    {
                      uri: "sip:201@203.0.113.40",
                      expires: 600,
                      q: 1,
                      received: "sip:192.0.2.50:41000;transport=tcp",
                      transport: "tcp",
                      path: [],
                      call_id: "reg-1",
                      cseq: 3,
                    },
                  ],
                },
              ],
            },
          };
        }
        if (frame.verb === "outbound_registrations") {
          return {
            status: "ok",
            result: {
              seq: 7,
              registrations: [
                {
                  aor: "sip:trunk@example.net",
                  registrar: "sip:registrar.example.net",
                  state: "failed",
                  expires_in: 0,
                  failure_count: 2,
                  status_code: 503,
                },
              ],
            },
          };
        }
        return { status: "ok", result: {} };
      },
    });
    cleanup.push(() => stub.stop());
    const sip = await SipClient.connect({ url: stub.url(), app: "dashboard", token: "t" });

    const events: AppEvent[] = [];
    sip.onAppEvent((event) => events.push(event));
    const runPromise = sip.onCall(() => undefined);
    await waitFor(() => stub.connectionCount() === 1);
    stub.pushEvent({
      event: "RegistrationChanged",
      app: "dashboard",
      payload: {
        seq: 42,
        aor: "sip:201@example.com",
        event: "refreshed",
        contacts: [
          {
            uri: "sip:201@203.0.113.40",
            expires: 600,
            q: 1,
            received: "sip:192.0.2.50:41000;transport=tcp",
          },
        ],
      },
    });
    await waitFor(() => events.length === 1);
    expect(events[0]?.kind).toBe("RegistrationChanged");
    const payload = events[0]?.payload as RegistrationChangedPayload;
    expect(payload.seq).toBe(42);
    expect(payload.contacts[0]?.received).toBe("sip:192.0.2.50:41000;transport=tcp");

    const registrations = await sip.registrations();
    expect(registrations.seq).toBe(41);
    expect(registrations.registrations.length).toBe(2);
    expect(registrations.registrations[1]?.contacts[0]?.cseq).toBe(3);
    expect(
      stub.received.some(
        (frame) => frame.verb === "registrations" && frame.args?.after === "sip:200@example.com",
      ),
    ).toBe(true);
    const outbound = await sip.outboundRegistrations();
    expect(outbound.registrations[0]?.status_code).toBe(503);
    expect(stub.received.some((frame) => frame.verb === "registrations")).toBe(true);

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

describe("SipClient.originate hands back the call it placed", () => {
  // siphon sends no StasisStart for a call its controller created, so the
  // placed call's events had nowhere to go until the channel was opened up
  // front. The 180 goes out ahead of the reply, since a fast one can overtake it.
  it("delivers every event on the placed channel, one ahead of the reply too", async () => {
    const event = (name: string, payload: Record<string, unknown>) => ({
      event: name,
      channel: "out-1",
      app: "agent-app",
      call_id: "call-uuid",
      sip_call_id: "sipcid@host",
      payload,
    });
    let originates = 0;
    const stub = await ControlStub.start({
      onCommand: (frame, socket) => {
        if (frame.verb !== "originate") {
          return { status: "ok", result: {} };
        }
        originates += 1;
        if (originates === 1) {
          stub.pushEvent(event("ChannelStateChange", { state: "ringing", code: 180 }), socket);
        }
        return {
          status: "ok",
          result: {
            channel: "out-1",
            call_id: "call-uuid",
            sip_call_id: "sipcid@host",
            state: "calling",
          },
        };
      },
    });
    cleanup.push(() => stub.stop());

    const sip = await SipClient.connect({ url: stub.url(), app: "agent-app", token: "t" });
    const running = sip.run();

    const call = await sip.originate("out-1", "sip:1001@pbx.example", { anchor: true });
    expect(call.channelId).toBe("out-1");
    expect(call.callId).toBe("call-uuid");
    expect(call.sipCallId).toBe("sipcid@host");
    expect(call.reattached).toBe(false);
    expect(call.payload).toMatchObject({ state: "calling" });

    stub.pushEvent(event("ChannelStateChange", { state: "answered", code: 200 }));
    stub.pushEvent(event("StasisEnd", { reason: "bye" }));
    const seen: Array<[string, unknown]> = [];
    for (let next = await call.nextEvent(); next !== null; next = await call.nextEvent()) {
      seen.push([next.kind, (next.payload as { state?: string } | null)?.state]);
    }
    expect(seen).toEqual([
      ["ChannelStateChange", "ringing"],
      ["ChannelStateChange", "answered"],
      ["StasisEnd", undefined],
    ]);

    // The id is free again once the call ends; while it rings it is not, and
    // the second originate is refused before anything is sent.
    await sip.originate("out-1", "sip:1001@pbx.example", { anchor: true });
    await expect(
      sip.originate("out-1", "sip:1002@pbx.example", { anchor: true }),
    ).rejects.toMatchObject({ code: "conflict" });
    expect(stub.received.filter((f) => f.verb === "originate")).toHaveLength(2);

    sip.shutdown();
    await running;
  });

  it("releases the channel when the server refuses the originate", async () => {
    let refuse = true;
    const stub = await ControlStub.start({
      onCommand: (frame) => {
        if (frame.verb === "originate" && refuse) {
          refuse = false;
          return { status: "error", error: { code: "not_found", message: "no route" } };
        }
        return { status: "ok", result: { channel: "out-1" } };
      },
    });
    cleanup.push(() => stub.stop());

    const sip = await SipClient.connect({ url: stub.url(), app: "agent-app", token: "t" });
    const running = sip.run();
    await expect(
      sip.originate("out-1", "sip:1001@pbx.example", { anchor: true }),
    ).rejects.toMatchObject({ code: "not_found" });
    const call = await sip.originate("out-1", "sip:1001@pbx.example", { anchor: true });
    expect(call.channelId).toBe("out-1");

    sip.shutdown();
    await running;
  });
});
