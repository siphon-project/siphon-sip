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
  isDialFinal,
  isTransferFinal,
  sipEventKind,
  SipVerb,
  transferOutcome,
  MODULE_SIP,
  SipClient,
  originateArgs,
  originateAorArgs,
  dialArgs,
  recordStartArgs,
  recordStopArgs,
} from "../src/index";
import type {
  BridgeFailedPayload,
  CallEvent,
  ChannelBridgedPayload,
  ChannelUnbridgedPayload,
  DialAnsweredPayload,
  DialBranchOutcome,
  DialBranchPayload,
  DialFailedPayload,
  DialogStateChangedPayload,
  PlayStartedPayload,
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
    expect(SipVerb.ReplacePeer).toBe("replace_peer");
    expect(SipVerb.Play).toBe("play");
    expect(SipVerb.Stop).toBe("stop");
    expect(SipVerb.Dtmf).toBe("dtmf");
    expect(SipVerb.Hold).toBe("hold");
    expect(SipVerb.Unhold).toBe("unhold");
    expect(SipVerb.StreamStart).toBe("stream_start");
    expect(SipVerb.StreamStop).toBe("stream_stop");
    expect(SipVerb.Dial).toBe("dial");
    expect(SipVerb.RecordStart).toBe("record_start");
    expect(SipVerb.RecordStop).toBe("record_stop");
    expect(SipVerb.Reject).toBe("reject");
    expect(SipVerb.Drop).toBe("drop");
    expect(SipVerb.CancelDial).toBe("cancel_dial");
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
    expect(sipEventKind("PeerReplaced")).toBe("PeerReplaced");
    expect(sipEventKind("ReplaceFailed")).toBe("ReplaceFailed");
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

  it("narrows a transfer verdict off an event and nothing else", () => {
    // TransferRequested is an *inbound* REFER somebody else asked for, not a
    // verdict on one of ours — reading it as an outcome would report a transfer
    // this app never started.
    const completed = transferOutcome({
      kind: "TransferCompleted",
      payload: JSON.parse('{"stage":"transferred","code":200,"reason":"OK"}'),
    });
    expect(completed?.stage).toBe("transferred");
    expect(completed?.code).toBe(200);

    expect(
      transferOutcome({ kind: "TransferProgress", payload: { stage: "accepted" } })?.stage,
    ).toBe("accepted");
    expect(transferOutcome({ kind: "TransferRequested", payload: {} })).toBeNull();
    expect(transferOutcome({ kind: "StasisEnd", payload: {} })).toBeNull();
    expect(transferOutcome({ kind: "TransferFailed", payload: null })).toBeNull();
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

  it("decodes DialogStateChanged and the aor on dial branches", () => {
    expect(sipEventKind("DialogStateChanged")).toBe("DialogStateChanged");
    const state: DialogStateChangedPayload = JSON.parse(
      '{"aor":"sip:202@example.com","state":"trying","direction":"initiator","leg_id":"leg-2",' +
        '"call_id":"a1@host","local_tag":"phone-tag","remote_tag":null,' +
        '"remote_identity":{"uri":"sip:15550100077@example.com","display_name":"Outside Line"}}',
    );
    expect(state.direction).toBe("initiator");
    expect(state.remote_tag).toBeNull();
    expect(state.remote_identity.display_name).toBe("Outside Line");

    const named: DialAnsweredPayload = JSON.parse(
      '{"leg_id":"leg-2","leg_sip_call_id":"b2@host","target":"sip:202@198.51.100.22:5060",' +
        '"aor":"sip:202@example.com","code":200}',
    );
    expect(named.aor).toBe("sip:202@example.com");
    const raw: DialBranchPayload = JSON.parse(
      '{"leg_id":"leg-1","leg_sip_call_id":"b1@host","target":"sip:15550100077@198.51.100.7"}',
    );
    expect(raw.aor).toBeUndefined();
  });

  it("marks exactly the dial outcomes as final", () => {
    expect(isDialFinal("DialAnswered")).toBe(true);
    expect(isDialFinal("DialFailed")).toBe(true);
    expect(isDialFinal("DialBranch")).toBe(false);
    expect(isDialFinal("DialBranchFailed")).toBe(false);
    expect(sipEventKind("DialBranch")).toBe("DialBranch");
  });

  it("decodes the dial event payloads", () => {
    // Byte-identical to what the server pushes on the dialling channel.
    const branch: DialBranchPayload = JSON.parse(
      '{"leg_id":"leg-1","leg_sip_call_id":"b1@host","target":"sip:204@example.com"}',
    );
    expect(branch.leg_sip_call_id).toBe("b1@host");

    const busy: DialBranchOutcome = JSON.parse(
      '{"leg_id":"leg-1","leg_sip_call_id":"b1@host","target":"sip:204@example.com",' +
        '"code":486,"reason":"Busy Here","cause":"rejected"}',
    );
    expect(busy.cause).toBe("rejected");
    expect(busy.code).toBe(486);

    const answered: DialAnsweredPayload = JSON.parse(
      '{"leg_id":"leg-2","leg_sip_call_id":"b2@host","target":"sip:205@example.com","code":200}',
    );
    expect(answered.leg_id).toBe("leg-2");

    const failed: DialFailedPayload = JSON.parse(
      '{"code":408,"reason":"Request Timeout","timed_out":true,"branches":[' +
        '{"leg_id":"leg-1","leg_sip_call_id":"b1@host","target":"sip:204@example.com",' +
        '"code":408,"reason":"Request Timeout","cause":"timeout"}]}',
    );
    expect(failed.timed_out).toBe(true);
    expect(failed.branches?.[0]?.leg_sip_call_id).toBe("b1@host");
    expect(failed.cause).toBeUndefined();
  });

  it("decodes the bridge-dial additions to the dial and play payloads", () => {
    // Byte-identical to what a `dial {on_answer: "bridge"}` pushes.
    const answered: DialAnsweredPayload = JSON.parse(
      '{"leg_id":"leg-2","leg_sip_call_id":"b2@host","target":"sip:205@192.0.2.7:5060",' +
        '"code":200,"aor":"sip:205@example.com","channel":"dial-bridge-leg-2"}',
    );
    expect(answered.channel).toBe("dial-bridge-leg-2");
    const orphaned: DialAnsweredPayload = JSON.parse(
      '{"leg_id":"leg-2","leg_sip_call_id":"b2@host","target":"sip:205@example.com",' +
        '"code":200,"channel":null}',
    );
    expect(orphaned.channel).toBeNull();

    const refused: DialBranchOutcome = JSON.parse(
      '{"leg_id":"leg-3","leg_sip_call_id":"b3@host","target":"sip:206@example.com",' +
        '"code":488,"reason":"Not Acceptable Here","cause":"bridge_failed"}',
    );
    expect(refused.cause).toBe("bridge_failed");

    const failed: DialFailedPayload = JSON.parse(
      '{"code":487,"reason":"Request Terminated","cause":"caller_hangup",' +
        '"timed_out":false,"branches":[]}',
    );
    expect(failed.cause).toBe("caller_hangup");
    expect(failed.timed_out).toBe(false);

    const ringback: PlayStartedPayload = JSON.parse(
      '{"source":"tone","origin":"ringback","play_id":7}',
    );
    expect(ringback.origin).toBe("ringback");
    const own: PlayStartedPayload = JSON.parse('{"source":"file","play_id":8}');
    expect(own.origin).toBeUndefined();
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

  it("answerAnchored always carries anchor, so no options still anchors", async () => {
    // With no options this has to mean "answer through the media engine on its
    // default profile" — an empty arg object would be indistinguishable from a
    // plain `answer`, which anchors nothing.
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.answerAnchored();
    await call.answerAnchored({ profile: "voice_ai", wsUri: "wss://ai.test/{call_id}" });
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "answer", target: { channel: "ch1" }, args: { anchor: true } },
      {
        module: MODULE_SIP,
        verb: "answer",
        target: { channel: "ch1" },
        args: { anchor: true, profile: "voice_ai", ws_uri: "wss://ai.test/{call_id}" },
      },
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

  it("drop sends the silent teardown verb, distinct from reject and hangup", async () => {
    // The three teardowns must reach the wire as three different verbs: two of
    // them answer the caller, and this one is the whole point of not doing that.
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.drop();
    await call.drop("no flow claims this number");
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "drop", target: { channel: "ch1" }, args: {} },
      {
        module: MODULE_SIP,
        verb: "drop",
        target: { channel: "ch1" },
        args: { reason: "no flow claims this number" },
      },
    ]);
  });

  it("cancelDial names the reason only when one is given", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.cancelDial();
    await call.cancelDial("max_wait");
    expect(transport.calls).toEqual([
      { module: MODULE_SIP, verb: "cancel_dial", target: { channel: "ch1" }, args: {} },
      {
        module: MODULE_SIP,
        verb: "cancel_dial",
        target: { channel: "ch1" },
        args: { reason: "max_wait" },
      },
    ]);
  });

  it("drop sends ban only when it is true", async () => {
    // Off is the server's default; sending `ban: false` would be noise, and a
    // string would be refused as bad_request.
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.drop("scanner", { ban: true });
    await call.drop(undefined, { ban: true });
    await call.drop("scanner", { ban: false });
    await call.drop("scanner", {});
    expect(transport.calls.map((recorded) => recorded.args)).toEqual([
      { reason: "scanner", ban: true },
      { ban: true },
      { reason: "scanner" },
      { reason: "scanner" },
    ]);
    expect(transport.calls.every((recorded) => recorded.verb === "drop")).toBe(true);
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

  it("route — sends reroute_after_progress only when true", async () => {
    const transport = new RecordingTransport({ channel: "ch1", state: "routing", targets: 3 });
    const call = makeCall(transport);
    await call.route([
      { uri: "sip:carrier1@gw1", timeout: 6, rerouteAfterProgress: true },
      { uri: "sip:carrier2@gw2", rerouteAfterProgress: false },
      { uri: "sip:carrier3@gw3", timeout: 6 },
    ]);
    expect(transport.calls).toEqual([
      {
        module: MODULE_SIP,
        verb: "route",
        target: { channel: "ch1" },
        args: {
          targets: [
            { uri: "sip:carrier1@gw1", timeout: 6, reroute_after_progress: true },
            // Off is the server's default and stays off the wire.
            { uri: "sip:carrier2@gw2" },
            { uri: "sip:carrier3@gw3", timeout: 6 },
          ],
          strategy: "sequential",
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
    // Until stopped: the one non-numeric repeat.
    await call.play({ file: "/prompts/hold.wav" }, { repeat: "inf" });
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
      { module: MODULE_SIP, verb: "play", target: { channel: "ch1" }, args: { file: "/prompts/hold.wav", repeat: "inf" } },
      { module: MODULE_SIP, verb: "stop", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "dtmf", target: { channel: "ch1" }, args: { digits: "123#", duration_ms: 100, volume_dbm0: -8 } },
      { module: MODULE_SIP, verb: "hold", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "unhold", target: { channel: "ch1" }, args: {} },
      { module: MODULE_SIP, verb: "stream_start", target: { channel: "ch1" }, args: { ws_uri: "ws://ai:9000/stream", mode: "tee", direction: "both", channels: 2 } },
      { module: MODULE_SIP, verb: "stream_stop", target: { channel: "ch1" }, args: { mode: "tee" } },
    ]);
  });

  it("stream — the mode always rides the frame, a tee carries its sample rate", async () => {
    const transport = new RecordingTransport();
    const call = makeCall(transport);
    await call.streamStart("wss://ai.example/stream");
    await call.streamStart("wss://ai.example/stream", {
      mode: "tee",
      direction: "caller",
      channels: 1,
      sampleRate: 16000,
    });
    await call.streamStart("wss://ai.example/agent", { mode: "bridge" });
    await call.streamStart("wss://ai.example/agent", { mode: "bridge", profile: "voice_ai" });
    await call.streamStop();
    await call.streamStop({ mode: "bridge" });
    expect(transport.calls).toEqual([
      // A tee and a bridge are opposites, so the plain call names the tee
      // rather than leaning on whatever the server defaults to.
      { module: MODULE_SIP, verb: "stream_start", target: { channel: "ch1" }, args: { ws_uri: "wss://ai.example/stream", mode: "tee" } },
      {
        module: MODULE_SIP,
        verb: "stream_start",
        target: { channel: "ch1" },
        args: { ws_uri: "wss://ai.example/stream", mode: "tee", direction: "caller", channels: 1, sample_rate: 16000 },
      },
      { module: MODULE_SIP, verb: "stream_start", target: { channel: "ch1" }, args: { ws_uri: "wss://ai.example/agent", mode: "bridge" } },
      {
        module: MODULE_SIP,
        verb: "stream_start",
        target: { channel: "ch1" },
        args: { ws_uri: "wss://ai.example/agent", mode: "bridge", profile: "voice_ai" },
      },
      { module: MODULE_SIP, verb: "stream_stop", target: { channel: "ch1" }, args: { mode: "tee" } },
      { module: MODULE_SIP, verb: "stream_stop", target: { channel: "ch1" }, args: { mode: "bridge" } },
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

  it("dial / recordStart / recordStop address the channel", async () => {
    const transport = new RecordingTransport({
      channel: "ch1",
      state: "dialing",
      targets: 3,
      strategy: "parallel",
      timeout: 30,
    });
    const call = makeCall(transport);
    const dialing = await call.dial([{ aor: "sip:204@pbx.example" }]);
    await call.recordStart({ direction: "both", maxDurationMs: 60000 });
    await call.recordStop("rec-1");
    expect(dialing).toMatchObject({ channel: "ch1", targets: 3 });
    expect(transport.calls).toEqual([
      {
        module: MODULE_SIP,
        verb: "dial",
        target: { channel: "ch1" },
        args: { targets: [{ aor: "sip:204@pbx.example" }] },
      },
      {
        module: MODULE_SIP,
        verb: "record_start",
        target: { channel: "ch1" },
        args: { direction: "both", max_duration_ms: 60000 },
      },
      {
        module: MODULE_SIP,
        verb: "record_stop",
        target: { channel: "ch1" },
        args: { recording_id: "rec-1" },
      },
    ]);
  });

  it("dial reads a bridge dial's reply", async () => {
    // Byte-identical to the server's reply to `dial {on_answer: "bridge"}`.
    const transport = new RecordingTransport({
      channel: "ch1",
      state: "dialing",
      on_answer: "bridge",
      group_id: "originate-group-9",
      targets: 2,
      strategy: "sequential",
      timeout: 20,
      total_timeout: 40,
      ringback: "ringback_eu",
      branches: [
        {
          leg_id: "leg-1",
          leg_sip_call_id: "b1@host",
          target: "sip:204@192.0.2.7:5060",
          aor: "sip:204@pbx.example",
        },
      ],
    });
    const call = makeCall(transport);
    const dialing = await call.dial([{ aor: "sip:204@pbx.example" }], {
      onAnswer: "bridge",
      strategy: "sequential",
      timeout: 20,
      ringback: "ringback_eu",
    });
    expect(dialing).toEqual({
      channel: "ch1",
      targets: 2,
      strategy: "sequential",
      timeout: 20,
      onAnswer: "bridge",
      groupId: "originate-group-9",
      totalTimeout: 40,
      ringback: "ringback_eu",
      branches: [
        {
          leg_id: "leg-1",
          leg_sip_call_id: "b1@host",
          target: "sip:204@192.0.2.7:5060",
          aor: "sip:204@pbx.example",
        },
      ],
    });
    expect(transport.calls[0]?.args).toEqual({
      targets: [{ aor: "sip:204@pbx.example" }],
      strategy: "sequential",
      timeout: 20,
      on_answer: "bridge",
      ringback: "ringback_eu",
    });

    // A connecting dial's reply carries none of the bridge fields.
    const plain = await makeCall(
      new RecordingTransport({ channel: "ch1", state: "dialing", targets: 1 }),
    ).dial([{ uri: "sip:1001@pbx.example" }]);
    expect(plain.onAnswer).toBeUndefined();
    expect(plain.groupId).toBeUndefined();
    expect(plain.branches).toBeUndefined();

    // `ringback: false` is a real value, not an absent one.
    const silent = await makeCall(
      new RecordingTransport({ channel: "ch1", on_answer: "bridge", ringback: false }),
    ).dial([{ aor: "sip:204@pbx.example" }], { onAnswer: "bridge", ringback: false });
    expect(silent.ringback).toBe(false);
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

describe("originate args map to the names the server parses", () => {
  it("is module-level: it creates the channel, so it carries no channel target", () => {
    // A target would make the substrate resolve an id that does not exist yet
    // and refuse the command.
    const args = originateArgs("out-1", "sip:1001@pbx.example", { anchor: true });
    expect(args).toEqual({ channel: "out-1", to: "sip:1001@pbx.example", media: true });
  });

  it("emits exactly one media plan per variant", () => {
    expect(
      originateArgs("out-1", "sip:1001@pbx.example", { anchor: true, profile: "voice_ai" }),
    ).toEqual({
      channel: "out-1",
      to: "sip:1001@pbx.example",
      media: true,
      profile: "voice_ai",
    });
    expect(originateArgs("out-1", "sip:1001@pbx.example", { sdp: "v=0\r\n" })).toEqual({
      channel: "out-1",
      to: "sip:1001@pbx.example",
      sdp: "v=0\r\n",
    });
    expect(
      originateArgs("out-1", "sip:1001@pbx.example", { body: "hi", contentType: "text/plain" }),
    ).toEqual({
      channel: "out-1",
      to: "sip:1001@pbx.example",
      body: "hi",
      content_type: "text/plain",
    });
  });

  it("snake_cases every option the server reads", () => {
    // A camelCase key is silently ignored server-side: the call still places,
    // just without the identity or privacy that was asked for.
    const args = originateArgs(
      "out-1",
      "sip:1001@pbx.example",
      { anchor: true },
      {
        from: "sip:alarm@pbx.example",
        fromDisplay: "Alarm",
        toDisplay: "Desk",
        nextHop: "sip:sbc.example:5060",
        pAssertedIdentity: "sip:+15550001@pbx.example",
        privacy: "restricted",
        headers: { "X-Reason": "wake-up" },
        timeout: 20,
        onLost: "continue",
        vars: { case: "wake" },
      },
    );
    expect(args).toEqual({
      channel: "out-1",
      to: "sip:1001@pbx.example",
      media: true,
      from: "sip:alarm@pbx.example",
      from_display: "Alarm",
      to_display: "Desk",
      next_hop: "sip:sbc.example:5060",
      p_asserted_identity: "sip:+15550001@pbx.example",
      privacy: "restricted",
      headers: { "X-Reason": "wake-up" },
      timeout: 20,
      on_lost: "continue",
      vars: { case: "wake" },
    });
  });

  it("sends a session timer as the object the server parses, with only the keys given", () => {
    expect(
      originateArgs(
        "out-1",
        "sip:1001@pbx.example",
        { anchor: true },
        { sessionTimer: { expires: 90, refresher: "uac" } },
      ),
    ).toEqual({
      channel: "out-1",
      to: "sip:1001@pbx.example",
      media: true,
      session_timer: { expires: 90, refresher: "uac" },
    });
    expect(
      originateArgs(
        "out-1",
        "sip:1001@pbx.example",
        { anchor: true },
        { sessionTimer: { expires: 1800, minSe: 120, refresher: "b2bua" } },
      ).session_timer,
    ).toEqual({ expires: 1800, min_se: 120, refresher: "b2bua" });
  });

  it("omits untouched options rather than sending undefined", () => {
    const args = originateArgs("out-1", "sip:1001@pbx.example", { anchor: true }, {});
    expect(Object.keys(args).sort()).toEqual(["channel", "media", "to"]);
  });
});

describe("originate {aor} args and reply", () => {
  it("sends aor in place of to, with the same options and the ring shaping", () => {
    // `to` beside `aor` is bad_request server-side, as is strategy /
    // total_timeout beside `to`; the two builders keep them apart.
    expect(
      originateAorArgs(
        "wake-201",
        "sip:201@pbx.example",
        { anchor: true },
        { from: "sip:reception@pbx.example", timeout: 25, onLost: "hangup" },
        { strategy: "sequential", totalTimeout: 60 },
      ),
    ).toEqual({
      channel: "wake-201",
      aor: "sip:201@pbx.example",
      media: true,
      from: "sip:reception@pbx.example",
      timeout: 25,
      on_lost: "hangup",
      strategy: "sequential",
      total_timeout: 60,
    });
    const bare = originateAorArgs("wake-201", "sip:201@pbx.example", { sdp: "v=0\r\n" });
    expect(bare).toEqual({ channel: "wake-201", aor: "sip:201@pbx.example", sdp: "v=0\r\n" });
    expect("to" in bare).toBe(false);
    expect("to" in originateArgs("out-1", "sip:1001@pbx.example", { anchor: true })).toBe(true);
    expect("aor" in originateArgs("out-1", "sip:1001@pbx.example", { anchor: true })).toBe(false);
  });

  it("is module-level and reads the group reply", async () => {
    const recorded: Recorded[] = [];
    const reply = {
      channel: "wake-201",
      group_id: "originate-group-3",
      aor: "sip:201@pbx.example",
      strategy: "parallel",
      total_timeout: 25,
      state: "calling",
      branches: [
        {
          leg_id: "leg-1",
          leg_sip_call_id: "l1@host",
          target: "sip:201@192.0.2.7:5060",
          aor: "sip:201@pbx.example",
        },
        {
          leg_id: "leg-2",
          leg_sip_call_id: "l2@host",
          target: "sip:201@198.51.100.4:5060",
          aor: "sip:201@pbx.example",
        },
      ],
    };
    const fakeControl = {
      commander: () => ({}),
      onEvent: () => undefined,
      command: (module: string | null, verb: string, target: unknown, args: unknown) => {
        recorded.push({ module, verb, target, args });
        return Promise.resolve(reply);
      },
    };
    const client = SipClient.wrap(fakeControl as never);
    const group = await client.originateAor(
      "wake-201",
      "sip:201@pbx.example",
      { anchor: true },
      undefined,
      { strategy: "parallel" },
    );
    expect(recorded).toEqual([
      {
        module: MODULE_SIP,
        verb: "originate",
        target: null,
        args: {
          channel: "wake-201",
          aor: "sip:201@pbx.example",
          media: true,
          strategy: "parallel",
        },
      },
    ]);
    expect(group).toEqual({
      channel: "wake-201",
      groupId: "originate-group-3",
      aor: "sip:201@pbx.example",
      strategy: "parallel",
      totalTimeout: 25,
      branches: reply.branches,
    });
  });
});

describe("dial args map to the target shapes the server parses", () => {
  it("sends a bare URI target as a string and an AoR as an object", () => {
    // The distinction the union exists for: `{aor}` forks to every registered
    // contact over that contact's own captured flow, which is the only way to
    // reach a phone registered on TCP, TLS or WSS behind NAT. The same text sent
    // as a URI is DNS-resolved and reaches none of them.
    expect(
      dialArgs([{ uri: "sip:1001@pbx.example" }, { aor: "sip:204@pbx.example" }]),
    ).toEqual({
      targets: ["sip:1001@pbx.example", { aor: "sip:204@pbx.example" }],
    });
  });

  it("sends the identity and media options under the server's names", () => {
    expect(
      dialArgs([{ uri: "sip:+15550177@trunk.example" }], {
        profile: "rtp_to_srtp",
        from: "sip:+15550100@trunk.example",
        fromDisplay: "Example Ltd",
        pAssertedIdentity: "<sip:+15550100@trunk.example>",
        privacy: "restricted",
      }),
    ).toEqual({
      targets: ["sip:+15550177@trunk.example"],
      profile: "rtp_to_srtp",
      from: "sip:+15550100@trunk.example",
      from_display: "Example Ltd",
      p_asserted_identity: "<sip:+15550100@trunk.example>",
      privacy: "restricted",
    });
  });

  it("keeps a URI target an object once it carries overrides", () => {
    expect(
      dialArgs([
        {
          uri: "sip:+15550177@trunk.example",
          nextHop: "sip:192.0.2.9:5060",
          headers: { "X-Carrier": "a" },
        },
      ]),
    ).toEqual({
      targets: [
        {
          uri: "sip:+15550177@trunk.example",
          next_hop: "sip:192.0.2.9:5060",
          headers: { "X-Carrier": "a" },
        },
      ],
    });
  });

  it("sends a target's called party as to, on either form", () => {
    // A divert: without `to` the B-leg keeps the caller's To user and goes out
    // addressed to the number originally dialled.
    expect(
      dialArgs([
        { uri: "sip:+15550199@trunk.example", to: "sip:+15550199@trunk.example" },
        { aor: "sip:204@pbx.example", to: "sip:+15550199@pbx.example" },
      ]),
    ).toEqual({
      targets: [
        { uri: "sip:+15550199@trunk.example", to: "sip:+15550199@trunk.example" },
        { aor: "sip:204@pbx.example", to: "sip:+15550199@pbx.example" },
      ],
    });
    expect(() =>
      dialArgs([{ uri: "sip:+15550199@trunk.example", to: 7 } as never]),
    ).toThrow(/to/);
  });

  it("refuses a target that names both a uri and an aor, and one that names neither", () => {
    // The server reads `aor` first and ignores a `uri` beside it, so this would
    // place a different call than the one written down — silently.
    expect(() =>
      dialArgs([
        { uri: "sip:1001@pbx.example", aor: "sip:204@pbx.example" } as never,
      ]),
    ).toThrow(/uri/);
    expect(() => dialArgs([{} as never])).toThrow(/uri/);
  });

  it("snake_cases the options and omits the ones left out", () => {
    expect(
      dialArgs([{ aor: "sip:204@pbx.example" }], {
        strategy: "sequential",
        timeout: 20,
        headers: { "X-Trace": "abc" },
      }),
    ).toEqual({
      targets: [{ aor: "sip:204@pbx.example" }],
      strategy: "sequential",
      timeout: 20,
      headers: { "X-Trace": "abc" },
    });
    // Nothing asked for, nothing sent: the server's own parallel / 30 s
    // defaults apply rather than a copy of them pinned here.
    expect(Object.keys(dialArgs([{ aor: "sip:204@pbx.example" }], {}))).toEqual([
      "targets",
    ]);
  });

  it("sends on_answer and every ringback form on a bridge dial", () => {
    const target = [{ aor: "sip:204@pbx.example" }];
    expect(dialArgs(target, { onAnswer: "bridge", ringback: "425/1000,0/4000*inf" })).toEqual({
      targets: [{ aor: "sip:204@pbx.example" }],
      on_answer: "bridge",
      ringback: "425/1000,0/4000*inf",
    });
    expect(dialArgs(target, { onAnswer: "bridge", ringback: true }).ringback).toBe(true);
    // `false` is "no ringback", not "unset": it must reach the wire.
    expect(dialArgs(target, { onAnswer: "bridge", ringback: false }).ringback).toBe(false);
    // Left out, the server's own ringback_eu default applies.
    expect(dialArgs(target, { onAnswer: "bridge" })).toEqual({
      targets: [{ aor: "sip:204@pbx.example" }],
      on_answer: "bridge",
    });
    expect(dialArgs(target, { onAnswer: "connect" }).on_answer).toBe("connect");
  });

  it("refuses a ringback without a bridge before anything is sent", () => {
    // The server answers bad_request / requires_bridge on a connecting dial.
    const target = [{ aor: "sip:204@pbx.example" }];
    expect(() => dialArgs(target, { ringback: "ringback_eu" })).toThrow(TypeError);
    expect(() => dialArgs(target, { ringback: false })).toThrow(/bridge/);
    expect(() => dialArgs(target, { onAnswer: "connect", ringback: true })).toThrow(TypeError);
  });

  it("refuses a ringback without a bridge on the call verb too", async () => {
    const transport = new RecordingTransport();
    await expect(
      makeCall(transport).dial([{ aor: "sip:204@pbx.example" }], { ringback: true }),
    ).rejects.toThrow(TypeError);
    expect(transport.calls).toEqual([]);
  });
});

describe("recording args map to the names the server parses", () => {
  it("sends only the selectors that were set", () => {
    expect(
      recordStartArgs({
        direction: "both",
        channels: "stereo",
        maxDurationMs: 60000,
        silenceMs: 4000,
        path: "/var/spool/siphon/greeting.wav",
      }),
    ).toEqual({
      direction: "both",
      channels: "stereo",
      max_duration_ms: 60000,
      silence_ms: 4000,
      path: "/var/spool/siphon/greeting.wav",
    });
    // `ingress` + `mono` are the server's defaults; pinning them here would stop
    // a caller that asked for nothing from tracking the server it talks to.
    expect(recordStartArgs()).toEqual({});
  });

  it("stops one recording by id, or every recording when none is named", () => {
    expect(recordStopArgs("rec-1")).toEqual({ recording_id: "rec-1" });
    // Absent, not null — which is what makes the server stop every recording on
    // the call rather than one named `null`.
    expect(recordStopArgs()).toEqual({});
  });
});
