#!/usr/bin/env python3
"""Example external control application for the siphon control plane.

Drives live B2BUA calls a script hands over with ``call.handover("<app>")`` (the
ARI *Stasis* model) over siphon's control WebSocket. Calls that are not handed
over are unaffected.

Two connection modes, same wire protocol (subprotocol ``siphon-control.v1``):

  * **outbound per-call-connect (the default)** — this app runs a WebSocket
    *server*; siphon dials it once per handed-over call and the accepting socket
    owns that call. No ``hello`` — the first frame is ``StasisStart``. This is
    the model to use for multi-pod / autoscaled controllers (siphon always dials
    *out*, so the "which pod owns the call" affinity problem cannot arise).

  * **inbound persistent** — this app is a WebSocket *client* that connects in to
    ``control.listen`` and owns calls assigned to it (round-robin). It sends a
    ``hello`` and can ``resync`` to re-attach its calls after a reconnect.

Select the mode with ``SIPHON_CONTROL_MODE`` (``outbound`` | ``inbound``).

The demo call flow answers each handed-over call, stamps a per-call variable,
holds briefly, then hangs up. The Phase-1 verb set is
``answer`` / ``progress`` / ``reject`` / ``hangup`` / ``refer`` /
``set_header`` / ``get_header`` (SIP adapter, ``module: "sip"``) plus the
substrate verbs ``resync`` / ``describe`` / ``set_var`` / ``get_var``.

Usage::

    pip install "websockets>=14"
    # outbound (default): siphon dials this server
    SIPHON_CONTROL_BIND=0.0.0.0:8443 IVR_APP_TOKEN=changeme-dev-token \\
        python control_client.py
    # inbound: this app dials siphon
    SIPHON_CONTROL_MODE=inbound IVR_APP_TOKEN=changeme-dev-token \\
        python control_client.py

See README.md for the matching siphon ``control:`` config and handover script.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os

import websockets

SUBPROTOCOL = "siphon-control.v1"

MODE = os.environ.get("SIPHON_CONTROL_MODE", "outbound").lower()
APP_NAME = os.environ.get("SIPHON_CONTROL_APP", "ivr-app")
TOKEN = os.environ.get("IVR_APP_TOKEN", "changeme-dev-token")

# inbound: where to dial siphon.
CONTROL_URL = os.environ.get("SIPHON_CONTROL_URL", "ws://127.0.0.1:9092/control/ws")
# outbound: where this app listens for siphon's per-call dials.
BIND = os.environ.get("SIPHON_CONTROL_BIND", "127.0.0.1:8443")

ANSWER_HOLD_SECONDS = 5.0

# Verbs the SIP adapter serves (routed with module="sip"); everything else is a
# substrate verb (hello/resync/describe/set_var/get_var) and omits the module.
_SIP_VERBS = {
    "answer", "progress", "reject", "hangup", "refer", "set_header", "get_header",
}


class ControlSession:
    """One control connection with request/reply correlation + event dispatch."""

    def __init__(self, connection) -> None:
        self._connection = connection
        self._ids = itertools.count(1)
        self._pending: dict[str, asyncio.Future] = {}
        self._tasks: set[asyncio.Task] = set()

    async def rpc(self, verb: str, *, target: dict | None = None,
                  args: dict | None = None) -> dict:
        """Send a command and await its correlated reply frame."""
        request_id = f"c-{next(self._ids)}"
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        command: dict = {
            "id": request_id,
            "type": "command",
            "verb": verb,
            "target": target or {},
            "args": args or {},
        }
        if verb in _SIP_VERBS:
            command["module"] = "sip"
        await self._connection.send(json.dumps(command))
        return await future

    async def read_loop(self) -> None:
        """Dispatch replies + events until the socket closes."""
        async for raw in self._connection:
            frame = json.loads(raw)
            kind = frame.get("type")
            if kind == "reply":
                future = self._pending.pop(frame.get("id", ""), None)
                if future is not None and not future.done():
                    future.set_result(frame)
            elif kind == "event":
                # Handle each event concurrently so a long call flow never blocks
                # the read loop (and thus never stalls another call).
                self._spawn(self._on_event(frame))

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _on_event(self, event: dict) -> None:
        name = event.get("event")
        channel = event.get("channel")
        if name == "StasisStart":
            # payload carries the full SIP context; sip_call_id joins CDR / HEP.
            print(f"[event] StasisStart {channel} sip_call_id={event.get('sip_call_id')}")
            await self._handle_call(channel)
        elif name == "StasisEnd":
            print(f"[event] StasisEnd {channel} reason={event.get('payload', {}).get('reason')}")
        else:
            print(f"[event] {name} {channel}")

    async def _handle_call(self, channel: str) -> None:
        target = {"channel": channel}
        answered = await self.rpc("answer", target=target, args={"code": 200})
        if answered.get("status") != "ok":
            print(f"[call] answer rejected: {answered.get('error')}")
            return
        # Per-call variables live on the control channel (drain with the call).
        await self.rpc("set_var", target=target, args={"key": "demo", "value": "1"})
        got = await self.rpc("get_var", target=target, args={"key": "demo"})
        print(f"[call] answered {channel}; demo={got.get('result', {}).get('value')}; "
              f"holding {ANSWER_HOLD_SECONDS}s")
        await asyncio.sleep(ANSWER_HOLD_SECONDS)
        hung = await self.rpc("hangup", target=target)
        print(f"[call] hangup {channel}: {hung.get('status')}")


async def run_inbound() -> None:
    """Client mode: dial siphon, hello, resync, then drive assigned calls."""
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with websockets.connect(
        CONTROL_URL, additional_headers=headers, subprotocols=[SUBPROTOCOL]
    ) as connection:
        print(f"[control] connected (inbound) to {CONTROL_URL}")
        session = ControlSession(connection)
        reader = asyncio.ensure_future(session.read_loop())
        hello = await session.rpc("hello", args={"app": APP_NAME, "protocol": 1})
        if hello.get("status") != "ok":
            reader.cancel()
            raise RuntimeError(f"hello rejected: {hello.get('error')}")
        print(f"[control] registered as {APP_NAME!r}")
        # Re-attach any calls we still own from a previous connection.
        resync = await session.rpc("resync")
        owned = resync.get("result", {}).get("channels", [])
        print(f"[control] resync re-attached {len(owned)} call(s)")
        for channel in owned:
            session._spawn(session._handle_call(channel["channel"]))
        await reader


async def _outbound_handler(connection) -> None:
    """Server mode: siphon dialed us for one call — we already own it."""
    # Verify the bearer token siphon presents (the app's own policy).
    presented = connection.request.headers.get("Authorization", "")
    if presented != f"Bearer {TOKEN}":
        print("[control] rejected outbound dial: bad/missing token")
        await connection.close(code=1008, reason="unauthorized")
        return
    print("[control] siphon dialed in (outbound per-call-connect) — we own this call")
    # No hello in outbound mode: the first frame is StasisStart. The websockets
    # server has already echoed the `siphon-control.v1` subprotocol on accept.
    await ControlSession(connection).read_loop()


async def run_outbound() -> None:
    """Server mode: listen for siphon's per-call dials."""
    host, _, port = BIND.partition(":")
    async with websockets.serve(
        _outbound_handler, host, int(port), subprotocols=[SUBPROTOCOL]
    ):
        print(f"[control] listening (outbound per-call-connect) on ws://{BIND}")
        await asyncio.Future()  # run forever


async def main() -> None:
    if MODE == "inbound":
        await run_inbound()
    elif MODE == "outbound":
        await run_outbound()
    else:
        raise SystemExit(f"SIPHON_CONTROL_MODE must be 'outbound' or 'inbound' (got {MODE!r})")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[control] interrupted")
