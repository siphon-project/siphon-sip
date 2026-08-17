#!/usr/bin/env python3
"""Example external control application for the siphon control plane — Python SDK.

Drives live B2BUA calls a script hands over with ``call.handover("ivr-app")`` (the
ARI *Stasis* model) over siphon's control WebSocket, using the ``siphon-control``
Python SDK. The SDK owns the wire completely: no manual JSON, no ``rpc()`` helper,
no request-id bookkeeping — you get a ``Call`` whose verbs read like an in-process
siphon script (``call.answer()`` / ``call.transfer(...)`` / ``call.hangup()``).

Inbound-persistent mode: this app is a WebSocket *client* that connects in to
``control.listen``, sends a ``hello``, and owns the calls assigned to it. On a
reconnect the SDK ``resync``s and re-dispatches the calls it still owns. (The
Python SDK ships the inbound-persistent client; for the per-call-connect model
where siphon dials the app, see the TypeScript example.)

The demo answers each handed-over call, stamps a per-call variable, holds
briefly, then hangs up. Calls that are not handed over are unaffected.

Install the SDK::

    pip install siphon-control            # once published
    # ...or from this repo, into the active venv:
    #   cd siphon-control-sdk/siphon-control && maturin develop

Run::

    IVR_APP_TOKEN=changeme-dev-token python control_client.py

See README.md for the matching siphon ``control:`` config and handover script.
"""
from __future__ import annotations

import asyncio
import os

from siphon_control import Call, ControlClient, ControlError

APP_NAME = os.environ.get("SIPHON_CONTROL_APP", "ivr-app")
TOKEN = os.environ.get("IVR_APP_TOKEN", "changeme-dev-token")
CONTROL_URL = os.environ.get("SIPHON_CONTROL_URL", "ws://127.0.0.1:9092/control/ws")

ANSWER_HOLD_SECONDS = 5.0

client = ControlClient(app=APP_NAME, token=TOKEN, url=CONTROL_URL)


@client.on_call
async def handle_call(call: Call) -> None:
    """Answer, stamp a per-call variable, hold, then hang up."""
    print(f"[call] StasisStart {call.channel_id} sip_call_id={call.sip_call_id}")
    try:
        await call.answer()
        # Per-call variables live on the control channel (drain with the call).
        await call.set_var("demo", "1")
        demo = await call.get_var("demo")
        print(f"[call] answered {call.channel_id}; demo={demo}; "
              f"holding {ANSWER_HOLD_SECONDS}s")
        await asyncio.sleep(ANSWER_HOLD_SECONDS)
        # Blind transfer instead of hanging up? -> await call.transfer("sip:agent@pbx")
        await call.hangup()
        print(f"[call] hung up {call.channel_id}")
    except ControlError as error:
        # A dead/unknown call is a typed `not_found`; a verb the server does not
        # implement yet is `unsupported_verb`. Never fatal to the other calls.
        print(f"[call] {call.channel_id} rejected: {error.code}")


async def main() -> None:
    print(f"[control] connecting to {CONTROL_URL} as {APP_NAME!r}")
    # run() connects + hello, then drives the supervised reconnect + resync loop,
    # dispatching each handed-over call to @client.on_call.
    await client.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[control] interrupted")
