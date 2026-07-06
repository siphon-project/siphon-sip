#!/usr/bin/env python3
"""Example external control client for the siphon control plane (experimental).

Connects to siphon's control WebSocket, registers as an application, and drives
calls that a B2BUA script hands over with ``call.handover("ivr-app")`` (the ARI
*Stasis* model). Calls that are not handed over are unaffected.

The proof-of-concept exposes two verbs, ``answer`` and ``hangup``; this app
answers each handed-over call, holds it briefly, then hangs up. Later phases add
play / dtmf / bridge / originate over the same protocol.

Usage:
    pip install "websockets>=14"
    IVR_APP_TOKEN=changeme-dev-token python control_client.py

See README.md for the matching siphon ``control:`` config and handover script.
"""
from __future__ import annotations

import asyncio
import itertools
import json
import os

import websockets

CONTROL_URL = os.environ.get("SIPHON_CONTROL_URL", "ws://127.0.0.1:9092/control/ws")
APP_NAME = os.environ.get("SIPHON_CONTROL_APP", "ivr-app")
TOKEN = os.environ.get("IVR_APP_TOKEN", "changeme-dev-token")
ANSWER_HOLD_SECONDS = 5.0


class ControlClient:
    """A minimal control-plane client with request/reply correlation."""

    def __init__(self, connection) -> None:
        self._connection = connection
        self._ids = itertools.count(1)
        self._pending: dict[str, asyncio.Future] = {}
        self._tasks: set[asyncio.Task] = set()

    async def rpc(self, verb: str, *, target: dict | None = None, args: dict | None = None) -> dict:
        """Send a command and await its correlated reply frame."""
        request_id = f"c-{next(self._ids)}"
        future: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        await self._connection.send(
            json.dumps(
                {
                    "id": request_id,
                    "type": "command",
                    "verb": verb,
                    "target": target or {},
                    "args": args or {},
                }
            )
        )
        return await future

    async def run(self) -> None:
        """Register as APP_NAME, then dispatch replies + events until close."""
        # Start reading first so the hello reply can be correlated.
        reader = asyncio.ensure_future(self._read_loop())
        hello = await self.rpc("hello", args={"app": APP_NAME, "protocol": 1})
        if hello.get("status") != "ok":
            reader.cancel()
            raise RuntimeError(f"hello rejected: {hello.get('error')}")
        print(f"[control] registered as {APP_NAME!r}")
        await reader

    async def _read_loop(self) -> None:
        async for raw in self._connection:
            frame = json.loads(raw)
            kind = frame.get("type")
            if kind == "reply":
                future = self._pending.pop(frame.get("id", ""), None)
                if future is not None and not future.done():
                    future.set_result(frame)
            elif kind == "event":
                # Handle each event concurrently so a long call flow never
                # blocks the read loop (and thus never stalls other calls).
                self._spawn(self._on_event(frame))

    def _spawn(self, coro) -> None:
        task = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _on_event(self, event: dict) -> None:
        name = event.get("event")
        channel = event.get("channel")
        if name == "StasisStart":
            print(f"[event] StasisStart {channel} {event.get('payload')}")
            await self._handle_call(channel)
        else:
            print(f"[event] {name} {channel}")

    async def _handle_call(self, channel: str) -> None:
        target = {"channel": channel}
        answered = await self.rpc("answer", target=target)
        if answered.get("status") != "ok":
            print(f"[call] answer rejected: {answered.get('error')}")
            return
        print(f"[call] answered {channel}; holding for {ANSWER_HOLD_SECONDS}s")
        await asyncio.sleep(ANSWER_HOLD_SECONDS)
        hung = await self.rpc("hangup", target=target)
        print(f"[call] hangup {channel}: {hung.get('status')}")


async def main() -> None:
    headers = {"Authorization": f"Bearer {TOKEN}"}
    async with websockets.connect(CONTROL_URL, additional_headers=headers) as connection:
        print(f"[control] connected to {CONTROL_URL}")
        await ControlClient(connection).run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[control] interrupted")
