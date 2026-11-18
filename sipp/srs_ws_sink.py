#!/usr/bin/env python3
"""WebSocket sink for the SIPREC live tee.

Counts what siphon-rtp sends to the `stream_start {mode: "tee"}` WebSocket and
prints one line per connection when it closes:

  SRS-SINK-VERDICT {"pass": true|false, "binary_frames": N, "binary_bytes": N, ...}

It passes when at least SRS_SINK_MIN_BYTES of binary audio arrived. A verdict
that never appears means the engine never dialled the sink.
"""
import asyncio
import json
import os
import pathlib
import time

import websockets

MIN_BYTES = int(os.environ.get("SRS_SINK_MIN_BYTES", "32000"))
PORT = int(os.environ.get("SRS_SINK_PORT", "9001"))
READY_FILE = os.environ.get("SRS_SINK_READY_FILE", "/tmp/srs-sink-ready")


async def handler(socket) -> None:
    frames = 0
    total = 0
    texts = []
    async for message in socket:
        if isinstance(message, (bytes, bytearray)):
            frames += 1
            total += len(message)
        else:
            texts.append(message[:300])
    print(
        "SRS-SINK-VERDICT "
        + json.dumps(
            {
                "pass": total >= MIN_BYTES,
                "binary_frames": frames,
                "binary_bytes": total,
                "min_bytes": MIN_BYTES,
                "text_frames": texts[:3],
            }
        ),
        flush=True,
    )


async def heartbeat() -> None:
    path = pathlib.Path(READY_FILE)
    while True:
        path.write_text(str(time.time()))
        await asyncio.sleep(2)


async def main() -> None:
    async with websockets.serve(handler, "0.0.0.0", PORT):
        print(f"srs sink listening on {PORT}", flush=True)
        await heartbeat()


asyncio.run(main())
