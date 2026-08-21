#!/usr/bin/env python3
"""Control application driving the `originate` acceptance test.

It stands in for a real out-of-process controller: it dials siphon's inbound
control WebSocket, says `hello`, and then places a call with an id **it** chose.
Everything it asserts is a property of the verb's contract, not of this app:

  1. **The id is the caller's.** The reply's `channel` is byte-identical to the
     id sent in `args.channel`; nothing was minted for us to look up. A second
     `originate` reusing that live id is refused `conflict` — distinguishable
     from `bad_request`, because retrying the same id can never succeed.

  2. **The accept is not the outcome.** The reply lands while the callee is
     still ringing. The UAS deliberately holds `180 Ringing` for a couple of
     seconds; the app records a monotonic timestamp for the reply and for the
     `answered` event and fails the run unless reply < ringing < answered. A
     synchronous originate would serialise this connection's whole command
     stream behind one ringing phone.

  3. **The identity crossed the wire.** The UAS scenario matches on the From,
     To, P-Asserted-Identity and custom header this app asked for, so a
     parameter that was accepted but never applied fails the run there.

  4. **Events correlate by the supplied id.** Every event carries `channel`
     equal to the id, so the app never needs a mapping table.

  5. **Hangup means hangup.** The app sends `hangup` on the answered call and
     requires the `StasisEnd` that follows.

One `ORIGINATE-VERDICT <json>` line is printed at the end. The CI step greps for
it and fails on `"pass": false`; a verdict that never appears is also a failure,
which is what catches the app never connecting at all.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import websockets

CONTROL_URL = os.environ.get("CONTROL_URL", "ws://172.20.0.150:9092/control/ws")
CONTROL_TOKEN = os.environ.get("CONTROL_TOKEN", "originate-test-token")
SUBPROTOCOL = "siphon-control.v1"

# The id this app chose before anything touched the network. Everything the app
# does afterwards is keyed on it.
CHANNEL_ID = os.environ.get("ORIGINATE_CHANNEL", "cb-0001")

# The callee (the SIPp UAS) and the identity the call must present.
TARGET = os.environ.get("ORIGINATE_TO", "sip:+15551000001@172.20.0.151:5060")
FROM_URI = os.environ.get("ORIGINATE_FROM", "sip:+15550000001@originate.test")
FROM_DISPLAY = "Callback"
ASSERTED = os.environ.get("ORIGINATE_PAI", "sip:+15550000001@originate.test")
CUSTOM_HEADER = ("X-Originate-Test", "acceptance")

# A plain G.711 offer, so the test needs no media backend at all — the media
# plan under test here is "the controller supplied the offer".
OFFER_SDP = (
    "v=0\r\n"
    "o=- 3141592653 3141592653 IN IP4 172.20.0.152\r\n"
    "s=originate\r\n"
    "c=IN IP4 172.20.0.152\r\n"
    "t=0 0\r\n"
    "m=audio 40000 RTP/AVP 0 101\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:101 telephone-event/8000\r\n"
    "a=sendrecv\r\n"
)

OVERALL_TIMEOUT_SECS = float(os.environ.get("ORIGINATE_TIMEOUT", "30"))


class Session:
    """One control connection, with request/reply correlation."""

    def __init__(self, socket) -> None:
        self._socket = socket
        self._next_id = 0
        self._replies: dict[str, dict] = {}
        self._events: list[dict] = []
        self._event_waiters: list[asyncio.Future] = []

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

    async def wait_event(self, predicate, timeout: float) -> dict:
        """Wait for the first event matching ``predicate``."""
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self._events):
                if predicate(event):
                    return self._events.pop(index)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("no matching event before the deadline")
            await self._pump(remaining)

    async def _pump(self, timeout: float = OVERALL_TIMEOUT_SECS) -> None:
        raw = await asyncio.wait_for(self._socket.recv(), timeout)
        frame = json.loads(raw)
        stamped = dict(frame)
        stamped["_at"] = time.monotonic()
        if frame.get("type") == "reply":
            self._replies[frame["id"]] = stamped
        elif frame.get("type") == "event":
            print(f"event {frame.get('event')} {json.dumps(frame.get('payload'))}",
                  flush=True)
            self._events.append(stamped)


def fail(checks: list, name: str, detail: str) -> None:
    checks.append({"check": name, "pass": False, "detail": detail})


def ok(checks: list, name: str, detail: str = "") -> None:
    checks.append({"check": name, "pass": True, "detail": detail})


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
            "hello", {"app": "originate-app", "protocol": 1}, module=None
        )
        if hello.get("status") != "ok":
            fail(checks, "hello", json.dumps(hello))
            return verdict(checks)
        ok(checks, "hello")

        # --- 1 + 2: place the call under our own id, and time the accept ----
        sent_at = time.monotonic()
        reply = await session.command("originate", {
            "channel": CHANNEL_ID,
            "to": TARGET,
            "from": FROM_URI,
            "from_display": FROM_DISPLAY,
            "p_asserted_identity": ASSERTED,
            "headers": {CUSTOM_HEADER[0]: CUSTOM_HEADER[1]},
            "sdp": OFFER_SDP,
            "timeout": 20,
        })
        accepted_at = reply.get("_at", time.monotonic())
        if reply.get("status") != "ok":
            fail(checks, "originate_accepted", json.dumps(reply))
            return verdict(checks)
        result = reply.get("result", {})
        if result.get("channel") != CHANNEL_ID:
            fail(checks, "caller_supplied_id",
                 f"reply channel {result.get('channel')!r} != {CHANNEL_ID!r}")
        else:
            ok(checks, "caller_supplied_id", CHANNEL_ID)
        if result.get("state") != "calling":
            fail(checks, "accept_state", json.dumps(result))
        else:
            ok(checks, "accept_state", "calling")
        if not result.get("sip_call_id"):
            fail(checks, "sip_call_id_returned", json.dumps(result))
        else:
            ok(checks, "sip_call_id_returned", result["sip_call_id"])

        # --- 1b: a duplicate id is refused, and distinguishably so ----------
        duplicate = await session.command("originate", {
            "channel": CHANNEL_ID,
            "to": TARGET,
            "sdp": OFFER_SDP,
        })
        code = (duplicate.get("error") or {}).get("code")
        if duplicate.get("status") == "error" and code == "conflict":
            ok(checks, "duplicate_id_is_conflict", code)
        else:
            fail(checks, "duplicate_id_is_conflict", json.dumps(duplicate))

        # --- 4: ringing arrives as an event on our id -----------------------
        ringing = await session.wait_event(
            lambda event: event.get("event") == "ChannelStateChange"
            and (event.get("payload") or {}).get("state") in ("ringing", "progress"),
            OVERALL_TIMEOUT_SECS,
        )
        if ringing.get("channel") != CHANNEL_ID:
            fail(checks, "ringing_correlates", json.dumps(ringing))
        else:
            ok(checks, "ringing_correlates",
               f"code={(ringing.get('payload') or {}).get('code')}")
        ringing_at = ringing.get("_at", time.monotonic())

        # --- 2: the accept came back before the far end did anything --------
        answered = await session.wait_event(
            lambda event: event.get("event") == "ChannelStateChange"
            and (event.get("payload") or {}).get("state") == "answered",
            OVERALL_TIMEOUT_SECS,
        )
        answered_at = answered.get("_at", time.monotonic())
        if answered.get("channel") != CHANNEL_ID:
            fail(checks, "answered_correlates", json.dumps(answered))
        else:
            ok(checks, "answered_correlates",
               f"code={(answered.get('payload') or {}).get('code')}")

        # The whole point of an asynchronous originate: the reply is the local
        # action, and it must land while the callee is still ringing.
        if accepted_at < ringing_at < answered_at:
            ok(checks, "accept_precedes_answer",
               f"accept +{accepted_at - sent_at:.3f}s, "
               f"ringing +{ringing_at - sent_at:.3f}s, "
               f"answered +{answered_at - sent_at:.3f}s")
        else:
            fail(checks, "accept_precedes_answer",
                 f"accept={accepted_at - sent_at:.3f} ringing={ringing_at - sent_at:.3f} "
                 f"answered={answered_at - sent_at:.3f}")
        # A synchronous originate would have blocked for the UAS's ring hold, so
        # the accept would be no faster than the answer. Require real slack.
        if answered_at - accepted_at < 1.0:
            fail(checks, "accept_is_not_the_outcome",
                 f"only {answered_at - accepted_at:.3f}s between accept and answer")
        else:
            ok(checks, "accept_is_not_the_outcome",
               f"{answered_at - accepted_at:.3f}s of ring after the accept")

        # --- 5: hang the answered call up, and require the StasisEnd --------
        hangup = await session.command(
            "hangup", {"reason": "acceptance test done"},
            target={"channel": CHANNEL_ID},
        )
        if hangup.get("status") != "ok":
            fail(checks, "hangup_accepted", json.dumps(hangup))
        else:
            ok(checks, "hangup_accepted")

        ended = await session.wait_event(
            lambda event: event.get("event") == "StasisEnd", OVERALL_TIMEOUT_SECS
        )
        if ended.get("channel") != CHANNEL_ID:
            fail(checks, "stasis_end_correlates", json.dumps(ended))
        else:
            ok(checks, "stasis_end_correlates",
               json.dumps(ended.get("payload")))

        # --- and the id is free again once the call is gone -----------------
        reused = await session.command("originate", {
            "channel": CHANNEL_ID,
            "to": "sip:+15559999999@172.20.0.253:5060",
            "sdp": OFFER_SDP,
            "timeout": 1,
        })
        reused_code = (reused.get("error") or {}).get("code")
        if reused.get("status") == "ok" or reused_code != "conflict":
            ok(checks, "id_is_free_after_teardown", reused_code or "ok")
        else:
            fail(checks, "id_is_free_after_teardown", json.dumps(reused))

    return verdict(checks)


def verdict(checks: list[dict]) -> bool:
    passed = all(check["pass"] for check in checks)
    print("ORIGINATE-VERDICT " + json.dumps({"pass": passed, "checks": checks}),
          flush=True)
    return passed


async def main() -> int:
    try:
        passed = await asyncio.wait_for(run(), OVERALL_TIMEOUT_SECS * 2)
    except Exception as error:  # noqa: BLE001 — the verdict is the report
        print("ORIGINATE-VERDICT " + json.dumps({
            "pass": False,
            "checks": [{"check": "run", "pass": False, "detail": repr(error)}],
        }), flush=True)
        return 1
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
