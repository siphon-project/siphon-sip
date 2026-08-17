#!/usr/bin/env python3
"""Example external control application for the siphon control plane — Python SDK.

Drives live B2BUA calls a script hands over with ``call.handover("ivr-app")`` (the
ARI *Stasis* model) over siphon's control WebSocket, using the ``siphon-control``
Python SDK. The SDK owns the wire completely: no manual JSON, no ``rpc()`` helper,
no request-id bookkeeping — you get a ``Call`` whose verbs read like an in-process
siphon script (``call.answer()`` / ``call.transfer(...)`` / ``call.hangup()``).

Two connection modes, same wire (subprotocol ``siphon-control.v1``), same
``@on_call`` decorator, same ``Call`` handle — only the transport differs:

  - **outbound per-call-connect (the default)** — this app is a WebSocket
    *server* (``ControlServer``); siphon dials it once per handed-over call and
    the accepting socket owns that call. No ``hello`` — the first frame is
    ``StasisStart``. Use this for multi-pod / autoscaled controllers (siphon
    always dials *out*, so the "which pod owns the call" affinity problem cannot
    arise).
  - **inbound persistent** — this app is a WebSocket *client* (``ControlClient``)
    that connects in to ``control.listen`` and owns calls assigned to it. It
    sends a ``hello`` and ``resync``s to re-attach its calls after a reconnect.

Select the mode with ``SIPHON_CONTROL_MODE`` (``outbound`` | ``inbound``).

The demo answers each handed-over call, stamps a per-call variable, holds
briefly, then hangs up. Calls that are not handed over are unaffected.

Install the SDK::

    pip install siphon-control            # once published
    # ...or from this repo, into the active venv:
    #   cd siphon-control-sdk/siphon-control && maturin develop

Run::

    # outbound (default): siphon dials this server
    SIPHON_CONTROL_BIND=0.0.0.0:8443 IVR_APP_TOKEN=changeme-dev-token python control_client.py
    # inbound: this app dials siphon
    SIPHON_CONTROL_MODE=inbound IVR_APP_TOKEN=changeme-dev-token python control_client.py

See README.md for the matching siphon ``control:`` config and handover script.
"""
from __future__ import annotations

import asyncio
import os

from siphon_control import Call, ControlClient, ControlError, ControlServer

MODE = os.environ.get("SIPHON_CONTROL_MODE", "outbound").lower()
APP_NAME = os.environ.get("SIPHON_CONTROL_APP", "ivr-app")
TOKEN = os.environ.get("IVR_APP_TOKEN", "changeme-dev-token")
CONTROL_URL = os.environ.get("SIPHON_CONTROL_URL", "ws://127.0.0.1:9092/control/ws")
BIND = os.environ.get("SIPHON_CONTROL_BIND", "127.0.0.1:8443")

ANSWER_HOLD_SECONDS = 5.0


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


async def run_inbound() -> None:
    """Inbound persistent: dial siphon, hello, resync, then drive assigned calls."""
    client = ControlClient(app=APP_NAME, token=TOKEN, url=CONTROL_URL)
    client.on_call(handle_call)
    print(f"[control] connecting (inbound) to {CONTROL_URL} as {APP_NAME!r}")
    # run() connects + hello, then drives the supervised reconnect + resync loop,
    # dispatching each handed-over call to handle_call.
    await client.run()


async def run_outbound() -> None:
    """Outbound per-call-connect: siphon dials this server once per handed-over call."""
    server = ControlServer(app=APP_NAME, token=TOKEN, bind=BIND)
    server.on_call(handle_call)
    # bind() resolves to the bound address (bind to `…:0` to learn an ephemeral
    # port before siphon dials in); serve() then accepts one call per dial forever.
    await server.bind()
    print(f"[control] listening (outbound per-call-connect) on ws://{server.local_addr}")
    await server.serve()


async def main() -> None:
    if MODE == "inbound":
        await run_inbound()
    elif MODE == "outbound":
        await run_outbound()
    else:
        raise SystemExit(
            f"SIPHON_CONTROL_MODE must be 'outbound' or 'inbound' (got {MODE!r})"
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[control] interrupted")
