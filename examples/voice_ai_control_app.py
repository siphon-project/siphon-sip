#!/usr/bin/env python3
"""
SIPhon voice-AI, control-plane variant — the external application.

The out-of-process half of examples/voice_ai_control.py. siphon has already
answered the call and bridged its audio to the WebSocket media server, so this
app inherits a live, already-connected channel: there is nothing to answer and no
media to wire. It owns what happens *next*.

The audio does not come through here. The AI reads and writes PCM on the
WebSocket the media engine dialled; this connection carries call control only.
Keeping them separate is the point — the media path survives a controller restart
(and `on_lost` in the handover script decides whether the call should).

Install the SDK:
    pip install siphon-control
    # ...or from this repo, into the active venv:
    #   cd siphon-control-sdk/siphon-control && maturin develop

Run:
    IVR_APP_TOKEN=changeme-dev-token python3 examples/voice_ai_control_app.py
"""
from __future__ import annotations

import asyncio
import os

from siphon_control import Call, ControlClient, ControlError

APP_NAME = os.environ.get("SIPHON_CONTROL_APP", "voice-ai-app")
TOKEN = os.environ.get("IVR_APP_TOKEN", "changeme-dev-token")
CONTROL_URL = os.environ.get("SIPHON_CONTROL_URL", "ws://127.0.0.1:9092/control/ws")

# How long to let the AI run before giving up on it. A real deployment ends the
# call when the AI decides it is done (over its own side channel) rather than on
# a wall-clock timer; this keeps the example self-contained.
MAX_CALL_SECONDS = 120.0

client = ControlClient(app=APP_NAME, token=TOKEN, url=CONTROL_URL)


@client.on_call
async def handle_call(call: Call) -> None:
    """Own one AI call. It arrives answered, with audio already bridged."""
    print(f"[call] StasisStart {call.channel_id} sip_call_id={call.sip_call_id}")
    try:
        # Stamp something the rest of the estate can correlate on. Per-call
        # variables live on the control channel and drain with the call.
        await call.set_var("handled_by", APP_NAME)

        # The AI is already talking to the caller over the WebSocket. Hold the
        # channel open until it is done, then release.
        await asyncio.sleep(MAX_CALL_SECONDS)

        # Handing off to a human instead of hanging up:
        #   await call.transfer("sip:agent@pbx.example.com")
        await call.hangup()
        print(f"[call] released {call.channel_id}")
    except ControlError as error:
        # A call that ended underneath us is a typed `not_found`; a verb this
        # server build does not implement is `unsupported_verb`. Neither is fatal
        # to the other calls this app owns.
        print(f"[call] {call.channel_id}: {error.code}")


async def main() -> None:
    print(f"[control] connecting to {CONTROL_URL} as {APP_NAME!r}")
    await client.run()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[control] interrupted")
