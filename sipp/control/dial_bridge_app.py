#!/usr/bin/env python3
"""Control application driving the `dial-bridge` acceptance test.

It stands in for an IVR at the moment it puts the caller through: the caller is
parked for it, it answers anchored on the media engine (the answer an IVR plays
its prompts over), then rings a phone registered at an AoR with
`dial {on_answer: "bridge"}` and lets siphon bridge the two when the phone picks
up. The phone and the caller are SIPp scenarios that assert what landed on the
wire; this asserts the verb's contract:

  1. A connecting dial is still refused on the answered caller, and a second
     bridge dial while the phone rings is refused too, both `invalid_state`.
  2. The bridge dial's reply is the local action: `state: dialing`, the default
     ringback, one branch for the one registered phone, named by `DialBranch`.
  3. The caller hears ringback once the phone alerts: `PlayStarted` with
     `origin: "ringback"`.
  4. The phone that answers gets `DialAnswered` with a channel of its own, and
     `ChannelBridged` arrives on both channels, with no `BridgeFailed`.
  5. The caller hangs up and the phone follows (the bridge's peer-hangup policy):
     `StasisEnd` on both channels, with no `hangup` sent by this app.

One `DIAL-BRIDGE-VERDICT <json>` line is printed at the end; the runner fails on
`"pass": false` and on a verdict that never appears.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

import websockets

from bridge_app import Session, fail, is_event, ok

CONTROL_URL = os.environ.get("CONTROL_URL", "ws://172.20.0.230:9092/control/ws")
CONTROL_TOKEN = os.environ.get("CONTROL_TOKEN", "dial-bridge-app-token")
APP_NAME = os.environ.get("CONTROL_APP", "dial-bridge-app")
SUBPROTOCOL = "siphon-control.v1"
PHONE_AOR = os.environ.get("DIAL_BRIDGE_AOR", "sip:2001@dialbridge.test")
READY_FILE = os.environ.get("CONTROL_READY_FILE", "/tmp/dial-bridge-app.ready")
EVENT_TIMEOUT_SECS = float(os.environ.get("DIAL_BRIDGE_EVENT_TIMEOUT", "30"))
OVERALL_TIMEOUT_SECS = float(os.environ.get("DIAL_BRIDGE_TIMEOUT", "90"))


def expect_refusal(checks: list, name: str, reply: dict, code: str, reason: str) -> None:
    """Require a typed refusal with exactly ``code`` and ``details.reason``."""
    error = reply.get("error") or {}
    details = error.get("details") or {}
    if (
        reply.get("status") == "error"
        and error.get("code") == code
        and (reason is None or details.get("reason") == reason)
    ):
        ok(checks, name, f"{code}/{reason}")
    else:
        fail(checks, name, f"expected {code}/{reason}, got {json.dumps(reply)}")


async def run() -> bool:
    checks: list[dict] = []
    headers = {"Authorization": f"Bearer {CONTROL_TOKEN}"}
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
        hello = await session.command("hello", {"app": APP_NAME, "protocol": 1}, module=None)
        if hello.get("status") != "ok":
            fail(checks, "hello", json.dumps(hello))
            return verdict(checks)
        ok(checks, "hello")
        with open(READY_FILE, "w", encoding="utf-8") as handle:
            handle.write("ready\n")

        start = await session.wait_event(lambda e: e.get("event") == "StasisStart")
        caller = start.get("channel")
        ok(checks, "stasis_start", caller)

        # Answer the caller anchored on the engine, as an IVR does before its
        # prompts.
        answered = await session.command(
            "answer",
            {"code": 200, "reason": "OK", "anchor": True, "profile": "bridge_relay"},
            target={"channel": caller},
        )
        if answered.get("status") != "ok":
            fail(checks, "answer_anchored", json.dumps(answered))
            return verdict(checks)
        ok(checks, "answer_anchored")

        # 1: a connecting dial cannot ring for an answered caller.
        expect_refusal(
            checks,
            "connecting_dial_refused_on_answered_caller",
            await session.command(
                "dial", {"targets": [{"aor": PHONE_AOR}]}, target={"channel": caller}
            ),
            "invalid_state",
            None,
        )

        # 2: the bridge dial.
        dialled = await session.command(
            "dial",
            {"targets": [{"aor": PHONE_AOR}], "on_answer": "bridge", "timeout": 20},
            target={"channel": caller},
        )
        result = dialled.get("result") or {}
        if (
            dialled.get("status") == "ok"
            and result.get("state") == "dialing"
            and result.get("on_answer") == "bridge"
            and result.get("ringback") == "ringback_eu"
            and len(result.get("branches") or []) == 1
        ):
            ok(checks, "bridge_dial_accepted", json.dumps(result))
        else:
            fail(checks, "bridge_dial_accepted", json.dumps(dialled))
            return verdict(checks)

        expect_refusal(
            checks,
            "second_bridge_dial_refused",
            await session.command(
                "dial",
                {"targets": [{"aor": PHONE_AOR}], "on_answer": "bridge"},
                target={"channel": caller},
            ),
            "invalid_state",
            "dial_in_progress",
        )

        await session.wait_event(lambda e: is_event(e, "DialBranch", caller))
        ok(checks, "dial_branch_named")

        # 3: ringback once the phone alerts.
        ringback = await session.wait_event(lambda e: is_event(e, "PlayStarted", caller))
        if (ringback.get("payload") or {}).get("origin") == "ringback":
            ok(checks, "ringback_started", json.dumps(ringback.get("payload")))
        else:
            fail(checks, "ringback_started", json.dumps(ringback))

        # 4: the phone answers and is bridged.
        answer = await session.wait_event(lambda e: is_event(e, "DialAnswered", caller))
        phone = (answer.get("payload") or {}).get("channel")
        if phone:
            ok(checks, "dial_answered_names_the_phone_channel", phone)
        else:
            fail(checks, "dial_answered_names_the_phone_channel", json.dumps(answer))
            return verdict(checks)
        await session.wait_event(lambda e: is_event(e, "ChannelBridged", caller))
        await session.wait_event(lambda e: is_event(e, "ChannelBridged", phone))
        ok(checks, "channel_bridged_on_both_channels")
        if session.seen(lambda e: e.get("event") in ("BridgeFailed", "DialFailed")):
            fail(checks, "no_failure", "a BridgeFailed or DialFailed arrived as well")
        else:
            ok(checks, "no_failure")

        # 5: the caller hangs up, the phone follows.
        await session.wait_event(lambda e: is_event(e, "StasisEnd", caller))
        ok(checks, "caller_stasis_end")
        try:
            await session.wait_event(lambda e: is_event(e, "StasisEnd", phone))
            ok(checks, "phone_followed_the_caller")
        except TimeoutError:
            fail(checks, "phone_followed_the_caller", "the phone outlived the caller")

    return verdict(checks)


def verdict(checks: list[dict]) -> bool:
    passed = all(check["pass"] for check in checks)
    print("DIAL-BRIDGE-VERDICT " + json.dumps({"pass": passed, "checks": checks}), flush=True)
    return passed


async def main() -> int:
    try:
        passed = await asyncio.wait_for(run(), OVERALL_TIMEOUT_SECS)
    except Exception as error:  # noqa: BLE001 — the verdict is the report
        print("DIAL-BRIDGE-VERDICT " + json.dumps({
            "pass": False,
            "checks": [{"check": "run", "pass": False, "detail": repr(error)}],
        }), flush=True)
        return 1
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
