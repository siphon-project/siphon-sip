/**
 * Wire-parity: the exact bytes this SDK serializes must equal what the server
 * emits and parses. The three pinned vectors below are the TypeScript twins of
 * the Rust `siphon-control-proto` `*_exact_bytes` tests — same field order, same
 * `module` omission for substrate verbs, same `null` target/args.
 */

import { describe, it, expect } from "vitest";

import { AsyncQueue } from "../src/internal";
import {
  Call,
  encodeCommand,
  isBridgeFinal,
  isTransferFinal,
  sipEventKind,
  SipVerb,
  MODULE_SIP,
} from "../src/index";
import type {
  BridgeFailedPayload,
  CallEvent,
  ChannelBridgedPayload,
  ChannelUnbridgedPayload,
  TransferOutcomePayload,
} from "../src/index";
import type { CommandTransport } from "../src/session";

describe("command wire bytes (byte-identical to the server)", () => {
  it("serializes an answer command exactly", () => {
    expect(
      encodeCommand("c-1", "sip", "answer", { channel: "ch1" }, { code: 200 }),
    ).toBe(
      '{"id":"c-1","type":"command","module":"sip","verb":"answer","target":{"channel":"ch1"},"args":{"code":200}}',
    );
  });

  it("serializes a substrate command with null target and args (no module)", () => {
    expect(encodeCommand("c-2", null, "resync", null, null)).toBe(
      '{"id":"c-2","type":"command","verb":"resync","target":null,"args":null}',
    );
  });

  it("serializes the hello handshake exactly", () => {
    expect(
      encodeCommand("c-0", null, "hello", null, { app: "ivr-app", protocol: 1 }),
    ).toBe(
      '{"id":"c-0","type":"command","verb":"hello","target":null,"args":{"app":"ivr-app","protocol":1}}',
    );
  });
});

describe("SipVerb wire tokens + event names", () => {
  it("maps verbs to the exact wire tokens", () => {
    expect(SipVerb.Answer).toBe("answer");
    expect(SipVerb.Ring).toBe("ring");
    expect(SipVerb.Progress).toBe("progress");
    expect(SipVerb.Hangup).toBe("hangup");
    expect(SipVerb.Route).toBe("route");
    expect(SipVerb.SetHeader).toBe("set_header");
    expect(SipVerb.GetHeader).toBe("get_header");
    expect(SipVerb.RemoveHeader).toBe("remove_header");
    expect(SipVerb.AcceptRefer).toBe("accept_refer");
    expect(SipVerb.RejectRefer).toBe("reject_refer");
    expect(SipVerb.Bridge).toBe("bridge");
    expect(SipVerb.Unbridge).toBe("unbridge");
    expect(SipVerb.Play).toBe("play");
    expect(SipVerb.Stop).toBe("stop");
    expect(SipVerb.Dtmf).toBe("dtmf");
    expect(SipVerb.Hold).toBe("hold");
    expect(SipVerb.Unhold).toBe("unhold");
    expect(SipVerb.StreamStart).toBe("stream_start");
    expect(SipVerb.StreamStop).toBe("stream_stop");
  });

  it("passes unknown + new event names through (forward-compatible)", () => {
    expect(sipEventKind("StasisStart")).toBe("StasisStart");
    expect(sipEventKind("ChannelDtmfReceived")).toBe("ChannelDtmfReceived");
    expect(sipEventKind("TransferRequested")).toBe("TransferRequested");
    expect(sipEventKind("TransferProgress")).toBe("TransferProgress");
    expect(sipEventKind("TransferCompleted")).toBe("TransferCompleted");
    expect(sipEventKind("TransferFailed")).toBe("TransferFailed");
    expect(sipEventKind("ChannelBridged")).toBe("ChannelBridged");
    expect(sipEventKind("BridgeFailed")).toBe("BridgeFailed");
    expect(sipEventKind("ChannelUnbridged")).toBe("ChannelUnbridged");
    expect(sipEventKind("SomethingNew")).toBe("SomethingNew");
  });

  it("marks exactly the terminal outbound-REFER verdicts as final", () => {
    // RFC 3515 §2.4.4: the 2xx to a REFER is only "accepted for processing", so
    // TransferProgress must never end an app's wait for the outcome.
    expect(isTransferFinal("TransferCompleted")).toBe(true);
    expect(isTransferFinal("TransferFailed")).toBe(true);
    expect(isTransferFinal("TransferProgress")).toBe(false);
    expect(isTransferFinal("TransferRequested")).toBe(false);
    expect(isTransferFinal("StasisEnd")).toBe(false);
  });

  it("marks exactly the terminal bridge verdicts as final", () => {
    // A bridge is two RFC 3261 §14 re-INVITEs, so the command reply is only the
    // local action; exactly one of these two ends the wait. An unbridge ends a
    // bridge that already formed, so it is not a verdict on forming one.
    expect(isBridgeFinal("ChannelBridged")).toBe(true);
    expect(isBridgeFinal("BridgeFailed")).toBe(true);
    expect(isBridgeFinal("ChannelUnbridged")).toBe(false);
    expect(isBridgeFinal("StasisEnd")).toBe(false);
  });

  it("decodes the bridge event payloads", () => {
    // Byte-identical to what the server pushes on both bridged channels.
    const bridged: ChannelBridgedPayload = JSON.parse(
      '{"peer_call_id":"call-b","peer_sip_call_id":"b@host",' +
        '"role":"anchor","anchored":true}',
    );
    expect(bridged.role).toBe("anchor");
    expect(bridged.anchored).toBe(true);
    expect(bridged.peer_sip_call_id).toBe("b@host");

    const failed: BridgeFailedPayload = JSON.parse(
      '{"stage":"offering_peer","code":488,"peer_sip_call_id":"b@host"}',
    );
    expect(failed.stage).toBe("offering_peer");
    expect(failed.code).toBe(488);

    const unbridged: ChannelUnbridgedPayload = JSON.parse(
      '{"peer_call_id":"call-b","peer_sip_call_id":"b@host","reason":"supervisor took over"}',
    );
    expect(unbridged.reason).toBe("supervisor took over");
  });

  it("decodes a transfer verdict payload", () => {
    // Byte-identical to the server's TransferFailed payload.
    const payload: TransferOutcomePayload = JSON.parse(
      '{"stage":"unauthorized","refer_to":"sip:carol@example.net",' +
        '"code":407,"reason":"Proxy Authentication Required","attempt":3}',
    );
    expect(payload.stage).toBe("unauthorized");
    expect(payload.code).toBe(407);
    expect(payload.attempt).toBe(3);
    expect(payload.refer_to).toBe("sip:carol@example.net");
  });
});

// A CommandTransport that records every call and returns a canned result.
interface Recorded {
  module: string | null;
  verb: string;
  target: unknown;
  args: unknown;
}

class RecordingTransport implements CommandTransport {
  readonly calls: Recorded[] = [];
  constructor(private readonly result: unknown = {}) {}
  command(module: string | null, verb: string, target: unknown, args: unknown): Promise<unknown> {
    this.calls.push({ module, verb, target, args });
    return Promise.resolve(this.result);
  }
}

function makeCall(transport: CommandTransport): Call {
  return new Call(transport, "ch1", "call-uuid", "sip@host", "ivr-app", null, false, new AsyncQueue<CallEvent>());
}

describe("Call verbs map to the in-process-mirrored wire verbs", () => {
  it("answer / progress / reject", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.answer();
    await call.answer({ code: 200, reason: "OK" });
    await call.progress();
    await call.reject(486, "Busy Here");
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "answer", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "answer", target: { channel: "ch1" }, args: { code: 200, reason: "OK" } },
      { module: MODULE_SIP, verb: "progress", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "reject", target: { channel: "ch1" }, args: { code: 486, reason: "Busy Here" } },
    ]);
  });

  // Alerting and early media are two verbs on the wire, not one verb plus a
  // status code the app has to know: `ring` emits its own token and carries no
  // body, `progress` is the one that can (RFC 3960 §3.1).
  it("ring and progress are separate verbs", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.ring();
    await call.ring("Alerting");
    await call.progress({ code: 183, body: "v=0\r\n", contentType: "application/sdp" });
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "ring", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "ring", target: { channel: "ch1" }, args: { reason: "Alerting" } },
      {
        module: MODULE_SIP,
        verb: "progress",
        target: { channel: "ch1" },
        args: { code: 183, body: "v=0\r\n", content_type: "application/sdp" },
      },
    ]);
  });

  it("terminate is primary, hangup is an alias — both send the hangup verb", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.terminate();
    await call.hangup("Q.850;cause=16");
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "hangup", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "hangup", target: { channel: "ch1" }, args: { reason: "Q.850;cause=16" } },
    ]);
  });

  it("refer / transfer / referReplaces", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.refer("sip:agent@pbx");
    await call.transfer("sip:queue@pbx");
    await call.referReplaces("sip:b@pbx", {
      callId: "abc",
      fromTag: "ft",
      toTag: "tt",
      earlyOnly: true,
    });
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "refer", target: { channel: "ch1" }, args: { to: "sip:agent@pbx" } },
      { module: MODULE_SIP, verb: "refer", target: { channel: "ch1" }, args: { to: "sip:queue@pbx" } },
      {
        module: MODULE_SIP,
        verb: "refer",
        target: { channel: "ch1" },
        args: {
          to: "sip:b@pbx",
          replaces: { call_id: "abc", from_tag: "ft", to_tag: "tt", early_only: true },
        },
      },
    ]);
  });

  it("header + var verbs (snake_case wire tokens, substrate vars carry no module)", async () => {
    const transport = new RecordingTransport({ value: "hdr-value" });
    const call = makeCall(transport);
    await call.setHeader("X-Tag", "1");
    expect(await call.getHeader("X-Tag")).toBe("hdr-value");
    await call.removeHeader("X-Tag");
    await call.setVar("queue", "support");
    expect(await call.getVar("queue")).toBe("hdr-value");
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "set_header", target: { channel: "ch1" }, args: { name: "X-Tag", value: "1" } },
      { module: MODULE_SIP, verb: "get_header", target: { channel: "ch1" }, args: { name: "X-Tag" } },
      { module: MODULE_SIP, verb: "remove_header", target: { channel: "ch1" }, args: { name: "X-Tag" } },
      { module: null, verb: "set_var", target: { channel: "ch1" }, args: { key: "queue", value: "support" } },
      { module: null, verb: "get_var", target: { channel: "ch1" }, args: { key: "queue" } },
    ]);
  });

  it("route — bare-URI + full-object targets, strategy + command headers", async () => {
    const transport = new RecordingTransport({ channel: "ch1", state: "routing", targets: 2 });
    const call = makeCall(transport);
    const result = await call.route(
      [
        "sip:carrier1@gw1",
        {
          uri: "sip:carrier2@gw2",
          nextHop: "sip:1.2.3.4:5060",
          headers: { "X-Foo": "bar" },
          timeout: 30,
        },
      ],
      "sequential",
      { "X-Trace": "abc" },
    );
    expect(result).toEqual({ channel: "ch1", state: "routing", targets: 2 });
    expect(transport.calls).toEqual([
      {
        module: MODULE_SIP,
        verb: "route",
        target: { channel: "ch1" },
        args: {
          targets: [
            "sip:carrier1@gw1",
            {
              uri: "sip:carrier2@gw2",
              next_hop: "sip:1.2.3.4:5060",
              headers: { "X-Foo": "bar" },
              timeout: 30,
            },
          ],
          strategy: "sequential",
          headers: { "X-Trace": "abc" },
        },
      },
    ]);
  });

  it("route — defaults strategy to sequential, omits headers when unset", async () => {
    const transport = new RecordingTransport({ channel: "ch1", state: "routing", targets: 1 });
    const call = makeCall(transport);
    await call.route(["sip:only@gw"]);
    expect(transport.calls).toEqual([
      {
        module: MODULE_SIP,
        verb: "route",
        target: { channel: "ch1" },
        args: { targets: ["sip:only@gw"], strategy: "sequential" },
      },
    ]);
  });

  it("acceptRefer / rejectRefer", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.acceptRefer({
      target: "sip:c@pbx",
      nextHop: "sip:sbc",
      mode: "terminate",
      profile: "rtp_passthrough",
    });
    await call.rejectRefer(603, "Decline");
    expect(transport.calls).toEqual([
      {
        module: MODULE_SIP,
        verb: "accept_refer",
        target: { channel: "ch1" },
        args: {
          target: "sip:c@pbx",
          next_hop: "sip:sbc",
          mode: "terminate",
          profile: "rtp_passthrough",
        },
      },
      { module: MODULE_SIP, verb: "reject_refer", target: { channel: "ch1" }, args: { code: 603, reason: "Decline" } },
    ]);
  });

  it("acceptRefer omits an unset profile", async () => {
    // Absent, not null — so the server's "inherit the call's profile" default
    // is what applies.
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.acceptRefer({ mode: "terminate" });
    expect(transport.calls[0]?.args).toEqual({ mode: "terminate" });
  });

  it("media verbs — play (file/dbId/blob), stop, dtmf, hold, unhold, stream", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.play({ file: "/prompts/welcome.wav" }, { repeat: 2 });
    await call.play({ dbId: 42 });
    // "hi" → base64 "aGk=".
    await call.play({ blob: new Uint8Array([104, 105]) }, { durationMs: 5000 });
    await call.playFile("/prompts/bye.wav");
    await call.stop();
    await call.dtmf("123#", { durationMs: 100, volumeDbm0: -8 });
    await call.hold();
    await call.unhold();
    await call.streamStart("ws://ai:9000/stream", { direction: "both", channels: 2 });
    await call.streamStop();
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "play", target: { channel: "ch1" }, args: { file: "/prompts/welcome.wav", repeat: 2 } },
      { module: MODULE_SIP, verb: "play", target: { channel: "ch1" }, args: { db_id: 42 } },
      { module: MODULE_SIP, verb: "play", target: { channel: "ch1" }, args: { blob: "aGk=", duration_ms: 5000 } },
      { module: MODULE_SIP, verb: "play", target: { channel: "ch1" }, args: { file: "/prompts/bye.wav" } },
      { module: MODULE_SIP, verb: "stop", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "dtmf", target: { channel: "ch1" }, args: { digits: "123#", duration_ms: 100, volume_dbm0: -8 } },
      { module: MODULE_SIP, verb: "hold", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "unhold", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "stream_start", target: { channel: "ch1" }, args: { ws_uri: "ws://ai:9000/stream", direction: "both", channels: 2 } },
      { module: MODULE_SIP, verb: "stream_stop", target: { channel: "ch1" }, args: {} },
    ]);
  });

  it("bridge / unbridge — the policy rides the frame, an unset one is omitted", async () => {
    const transport = new RecordingTransport({
      channel: "ch1",
      with: "ch2",
      call_id: "call-a",
      peer_call_id: "call-b",
      anchored: true,
      on_peer_hangup: "hold",
      state: "bridging",
    });
    const call = makeCall(transport);
    const result = await call.bridge("ch2", { onPeerHangup: "hold" });
    // The reply is the local action; the audio meeting is the event.
    expect(result).toMatchObject({ with: "ch2", state: "bridging" });
    await call.bridge("ch3");
    await call.unbridge("supervisor took over");
    await call.unbridge();
    expect(transport.calls).toEqual([
      {
        module: MODULE_SIP,
        verb: "bridge",
        target: { channel: "ch1" },
        args: { with: "ch2", on_peer_hangup: "hold" },
      },
      // Absent, not null — so the server's "hangup" default is what applies.
      { module: MODULE_SIP, verb: "bridge", target: { channel: "ch1" }, args: { with: "ch3" } },
      {
        module: MODULE_SIP,
        verb: "unbridge",
        target: { channel: "ch1" },
        args: { reason: "supervisor took over" },
      },
      { module: MODULE_SIP, verb: "unbridge", target: { channel: "ch1" }, args: {} },
    ]);
  });

  it("removeHeader emits the remove_header verb", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.removeHeader("X-Foo");
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "remove_header", target: { channel: "ch1" }, args: { name: "X-Foo" } },
    ]);
  });
});
