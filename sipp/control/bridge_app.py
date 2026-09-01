#!/usr/bin/env python3
"""Control application driving the `bridge` acceptance test.

It stands in for a controller doing callback-and-connect: it takes an inbound
call siphon parked for it, places a second one, joins the two, parts them, joins
them again, and then watches what a hangup on one side does to the other.

What this app asserts is the verb's *contract*. Whether audio actually meets is
asserted elsewhere and on purpose — no reply and no event on this rail can show
it, so the media engine's own per-leg packet counters (carried out as siphon's
`MEDIA` CDR) are the oracle for that, and the SIPp scenarios assert what landed
on the SIP wire.

  1. **Every refusal is typed and distinguishable.** Bridging with no second
     leg, to itself, to a channel that does not exist, with an unknown
     `on_peer_hangup`, to a leg that has not answered, to a leg that is already
     bridged, and unbridging a leg that never was — seven refusals, and the app
     requires each to come back with its own code. A single "error" for all of
     them would let a controller retry something that can never work.

  2. **The reply is the local action, not the outcome.** `bridge` answers
     `state: "bridging"`; the media meeting is a `ChannelBridged` event, and it
     arrives on **both** channels, because a bridge is two re-INVITEs and either
     party can refuse.

  3. **Unbridge parts without ending.** After `unbridge` both channels are still
     there — no `StasisEnd` — and can be bridged again.

  4. **The peer-hangup policy is real.** The caller hangs up; with the default
     policy the second leg goes too, and the app requires that `StasisEnd`
     without having sent a `hangup` for it.

One `BRIDGE-VERDICT <json>` line is printed at the end. The CI step greps for it
and fails on `"pass": false`; a verdict that never appears is also a failure,
which is what catches the app never connecting at all.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import websockets

CONTROL_URL = os.environ.get("CONTROL_URL", "ws://172.20.0.170:9092/control/ws")
CONTROL_TOKEN = os.environ.get("CONTROL_TOKEN", "bridge-app-token")
APP_NAME = os.environ.get("CONTROL_APP", "bridge-app")
SUBPROTOCOL = "siphon-control.v1"

# The id this app chooses for the leg it places. The inbound leg's id is minted
# by siphon at handover and arrives on the StasisStart.
PEER_CHANNEL = os.environ.get("BRIDGE_PEER_CHANNEL", "bridge-b")
PEER_TARGET = os.environ.get("BRIDGE_PEER_TO", "sip:+15551000002@172.20.0.172:5060")
PEER_FROM = os.environ.get("BRIDGE_PEER_FROM", "sip:+15550000002@bridge.test")

# How long the two parties are left bridged, in seconds. Long enough for SIPp to
# stream its sample through the engine in both directions so the media CDR has
# something to count.
TALK_SECS = float(os.environ.get("BRIDGE_TALK_SECS", "3"))

# What the application answers the caller with. Held rather than connected
# (RFC 3264 §8.4; RFC 6337 §3.1 prefers a direction attribute to c=0.0.0.0):
# there is nobody on the other side yet, so promising audio would be a lie and
# an address the caller streams into a black hole. The bridge re-offers this leg
# onto the engine afterwards, which is the whole point.
HELD_ANSWER_SDP = (
    "v=0\r\n"
    "o=- 3141592653 3141592653 IN IP4 172.20.0.171\r\n"
    "s=bridge\r\n"
    "c=IN IP4 172.20.0.171\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 8\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=ptime:30\r\n"
    "a=inactive\r\n"
)

# Touched once the application is connected and has said hello. The compose
# healthcheck waits for it before the caller is allowed to dial: siphon parks a
# handed-over call only if a controller is *there*, and an INVITE that arrives
# while this container is still installing its dependencies is answered by the
# handoff default instead — which looks like a bridge bug and is not one.
READY_FILE = os.environ.get("CONTROL_READY_FILE", "/tmp/bridge-app.ready")

EVENT_TIMEOUT_SECS = float(os.environ.get("BRIDGE_EVENT_TIMEOUT", "30"))
OVERALL_TIMEOUT_SECS = float(os.environ.get("BRIDGE_TIMEOUT", "90"))


class Session:
    """One control connection, with request/reply correlation."""

    def __init__(self, socket) -> None:
        self._socket = socket
        self._next_id = 0
        self._replies: dict[str, dict] = {}
        self._events: list[dict] = []

    async def command(self, verb: str, args: dict, module: str | None = "sip",
                      target: dict | None = None) -> dict:
        """Send one command and return its correlated reply frame."""
        self._next_id += 1
        request_id = f"c-{self._next_id}"
        frame = {"id": request_id, "type": "command", "verb": verb, "args": args}
        if module is not None:
            frame["module"] = module
        if target is not None:
            frame["target"] = target
        await self._socket.send(json.dumps(frame))
        while request_id not in self._replies:
            await self._pump()
        return self._replies.pop(request_id)

    async def wait_event(self, predicate, timeout: float = EVENT_TIMEOUT_SECS) -> dict:
        """Wait for (and consume) the first event matching ``predicate``."""
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self._events):
                if predicate(event):
                    return self._events.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no matching event before the deadline")
            await self._pump(remaining)

    def seen(self, predicate) -> bool:
        """Whether a matching event is already in the backlog."""
        return any(predicate(event) for event in self._events)

    async def drain(self, seconds: float) -> None:
        """Keep reading frames for `seconds` (so the backlog stays current)."""
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                await self._pump(remaining)
            except asyncio.TimeoutError:
                return

    async def _pump(self, timeout: float = EVENT_TIMEOUT_SECS) -> None:
        raw = await asyncio.wait_for(self._socket.recv(), timeout)
        frame = json.loads(raw)
        if frame.get("type") == "reply":
            self._replies[frame["id"]] = frame
        elif frame.get("type") == "event":
            print(
                f"event {frame.get('event')} channel={frame.get('channel')} "
                f"{json.dumps(frame.get('payload'))}",
                flush=True,
            )
            self._events.append(frame)


def fail(checks: list, name: str, detail: str) -> None:
    checks.append({"check": name, "pass": False, "detail": detail})


def ok(checks: list, name: str, detail: str = "") -> None:
    checks.append({"check": name, "pass": True, "detail": detail})


def expect_error(checks: list, name: str, reply: dict, code: str) -> None:
    """Require a typed refusal with exactly ``code``."""
    actual = (reply.get("error") or {}).get("code")
    if reply.get("status") == "error" and actual == code:
        ok(checks, name, code)
    else:
        fail(checks, name, f"expected {code}, got {json.dumps(reply)}")


def is_event(event: dict, name: str, channel: str) -> bool:
    return event.get("event") == name and event.get("channel") == channel


async def run() -> bool:
    checks: list[dict] = []

    headers = {"Authorization": f"Bearer {CONTROL_TOKEN}"}
    # websockets renamed extra_headers -> additional_headers in 14.0.
    try:
        connector = websockets.connect(
            CONTROL_URL, subprotocols=[SUBPROTOCOL], additional_headers=headers
        )
    except TypeError:
        connector = websockets.connect(
            CONTROL_URL, subprotocols=[SUBPROTOCOL], extra_headers=headers
        )

    async with connector as socket:
        session = Session(socket)

        hello = await session.command(
            "hello", {"app": APP_NAME, "protocol": 1}, module=None
        )
        if hello.get("status") != "ok":
            fail(checks, "hello", json.dumps(hello))
            return verdict(checks)
        ok(checks, "hello")
        with open(READY_FILE, "w", encoding="utf-8") as handle:
            handle.write("ready\n")

        # --- the parked inbound leg -----------------------------------------
        start = await session.wait_event(
            lambda event: event.get("event") == "StasisStart", EVENT_TIMEOUT_SECS
        )
        caller = start.get("channel")
        if not caller:
            fail(checks, "stasis_start_has_channel", json.dumps(start))
            return verdict(checks)
        ok(checks, "stasis_start_has_channel", caller)

        # Answer the caller, held. Nothing is connected to it yet.
        answered_caller = await session.command(
            "answer",
            {"code": 200, "reason": "OK", "body": HELD_ANSWER_SDP,
             "content_type": "application/sdp"},
            target={"channel": caller},
        )
        if answered_caller.get("status") != "ok":
            fail(checks, "answer_accepted", json.dumps(answered_caller))
            return verdict(checks)
        ok(checks, "answer_accepted")

        # --- 1: the refusals that need no second leg ------------------------
        expect_error(
            checks,
            "bridge_without_with_is_bad_request",
            await session.command("bridge", {}, target={"channel": caller}),
            "bad_request",
        )
        expect_error(
            checks,
            "bridge_to_itself_is_bad_request",
            await session.command("bridge", {"with": caller}, target={"channel": caller}),
            "bad_request",
        )
        expect_error(
            checks,
            "bridge_to_an_unknown_channel_is_not_found",
            await session.command(
                "bridge", {"with": "no-such-channel"}, target={"channel": caller}
            ),
            "not_found",
        )
        expect_error(
            checks,
            "unknown_peer_hangup_policy_is_bad_request",
            await session.command(
                "bridge",
                {"with": PEER_CHANNEL, "on_peer_hangup": "park"},
                target={"channel": caller},
            ),
            "bad_request",
        )
        expect_error(
            checks,
            "unbridge_of_an_unbridged_leg_is_invalid_state",
            await session.command("unbridge", {}, target={"channel": caller}),
            "invalid_state",
        )

        # --- place the second leg -------------------------------------------
        placed = await session.command("originate", {
            "channel": PEER_CHANNEL,
            "to": PEER_TARGET,
            "from": PEER_FROM,
            "media": True,
            "profile": "bridge_relay",
            "timeout": 20,
        })
        if placed.get("status") != "ok":
            fail(checks, "originate_accepted", json.dumps(placed))
            return verdict(checks)
        ok(checks, "originate_accepted", json.dumps(placed.get("result")))

        # --- 1b: the callee is still ringing, so bridging it is refused -----
        # The UAS holds 180 for two seconds on purpose; the originate reply came
        # back during that ring, so this lands while the leg is unanswered. It
        # must read differently from "no such leg".
        expect_error(
            checks,
            "bridge_to_an_unanswered_leg_is_invalid_state",
            await session.command(
                "bridge", {"with": PEER_CHANNEL}, target={"channel": caller}
            ),
            "invalid_state",
        )

        answered = await session.wait_event(
            lambda event: is_event(event, "ChannelStateChange", PEER_CHANNEL)
            and (event.get("payload") or {}).get("state") == "answered",
            EVENT_TIMEOUT_SECS,
        )
        ok(checks, "peer_answered", json.dumps(answered.get("payload")))

        # --- 2: join them ----------------------------------------------------
        joined = await session.command(
            "bridge", {"with": PEER_CHANNEL}, target={"channel": caller}
        )
        if joined.get("status") != "ok":
            fail(checks, "bridge_accepted", json.dumps(joined))
            return verdict(checks)
        result = joined.get("result") or {}
        if result.get("state") != "bridging":
            fail(checks, "bridge_reply_is_the_local_action", json.dumps(result))
        else:
            ok(checks, "bridge_reply_is_the_local_action", "bridging")
        if result.get("anchored") is not True:
            fail(checks, "bridge_is_anchored", json.dumps(result))
        else:
            ok(checks, "bridge_is_anchored", "true")
        # The caller was answered by this application and has no media session;
        # the leg we placed was anchored on the engine. The anchor has to be the
        # one with something to keep, or the bridge would delete the only media
        # session it has and drop both parties out of the media path.
        if result.get("anchor") != PEER_CHANNEL:
            fail(checks, "anchor_is_the_leg_with_the_media",
                 f"expected {PEER_CHANNEL}, got {json.dumps(result)}")
        else:
            ok(checks, "anchor_is_the_leg_with_the_media", PEER_CHANNEL)

        # The verdict, on BOTH channels: a bridge either party refuses is not a
        # bridge, so one ChannelBridged would not be enough.
        await session.wait_event(lambda e: is_event(e, "ChannelBridged", caller))
        await session.wait_event(lambda e: is_event(e, "ChannelBridged", PEER_CHANNEL))
        ok(checks, "channel_bridged_on_both_legs")
        if session.seen(lambda e: e.get("event") == "BridgeFailed"):
            fail(checks, "no_bridge_failure", "a BridgeFailed arrived as well")
        else:
            ok(checks, "no_bridge_failure")

        # --- 1c: a leg that is already bridged is refused -------------------
        expect_error(
            checks,
            "bridging_an_already_bridged_leg_is_invalid_state",
            await session.command(
                "bridge", {"with": PEER_CHANNEL}, target={"channel": caller}
            ),
            "invalid_state",
        )

        # Let the two parties talk. SIPp is streaming its sample through the
        # engine from both sides; the media CDR counts what arrives.
        await session.drain(TALK_SECS)

        # --- 3: part them, and require that neither call ended --------------
        parted = await session.command(
            "unbridge", {"reason": "acceptance-unbridge"}, target={"channel": caller}
        )
        if parted.get("status") != "ok":
            fail(checks, "unbridge_accepted", json.dumps(parted))
            return verdict(checks)
        ok(checks, "unbridge_accepted", json.dumps(parted.get("result")))
        await session.wait_event(lambda e: is_event(e, "ChannelUnbridged", caller))
        await session.wait_event(lambda e: is_event(e, "ChannelUnbridged", PEER_CHANNEL))
        ok(checks, "channel_unbridged_on_both_legs")
        if session.seen(lambda e: e.get("event") == "StasisEnd"):
            fail(checks, "unbridge_does_not_end_either_call",
                 "a StasisEnd arrived during the unbridge")
        else:
            ok(checks, "unbridge_does_not_end_either_call")

        # --- join them again ------------------------------------------------
        # The anchor's engine session is now a live two-party relay, so this
        # second join renegotiates it in place rather than replacing it.
        rejoined = await session.command(
            "bridge", {"with": PEER_CHANNEL}, target={"channel": caller}
        )
        if rejoined.get("status") != "ok":
            fail(checks, "rebridge_accepted", json.dumps(rejoined))
            return verdict(checks)
        ok(checks, "rebridge_accepted", json.dumps(rejoined.get("result")))
        await session.wait_event(lambda e: is_event(e, "ChannelBridged", caller))
        await session.wait_event(lambda e: is_event(e, "ChannelBridged", PEER_CHANNEL))
        ok(checks, "rebridged_on_both_legs")

        await session.drain(TALK_SECS)

        # --- 4: the caller hangs up; the peer must follow -------------------
        # Nothing below sends `hangup` for the second leg. Its StasisEnd can
        # only come from the peer-hangup policy the bridge was formed with.
        caller_end = await session.wait_event(
            lambda e: is_event(e, "StasisEnd", caller), EVENT_TIMEOUT_SECS
        )
        ok(checks, "caller_stasis_end", json.dumps(caller_end.get("payload")))
        try:
            peer_end = await session.wait_event(
                lambda e: is_event(e, "StasisEnd", PEER_CHANNEL), EVENT_TIMEOUT_SECS
            )
            ok(checks, "peer_hangup_policy_tore_the_survivor_down",
               json.dumps(peer_end.get("payload")))
        except TimeoutError:
            fail(checks, "peer_hangup_policy_tore_the_survivor_down",
                 "the survivor outlived its bridge partner")

    return verdict(checks)


def verdict(checks: list[dict]) -> bool:
    passed = all(check["pass"] for check in checks)
    print("BRIDGE-VERDICT " + json.dumps({"pass": passed, "checks": checks}), flush=True)
    return passed


async def main() -> int:
    try:
        passed = await asyncio.wait_for(run(), OVERALL_TIMEOUT_SECS)
    except Exception as error:  # noqa: BLE001 — the verdict is the report
        print("BRIDGE-VERDICT " + json.dumps({
            "pass": False,
            "checks": [{"check": "run", "pass": False, "detail": repr(error)}],
        }), flush=True)
        return 1
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
