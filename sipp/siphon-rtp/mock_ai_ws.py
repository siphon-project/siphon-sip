#!/usr/bin/env python3
"""Mock voice-AI WebSocket media server for the real-engine functional test.

The `ws_uri` profile flag makes siphon-rtp hand leg A's decoded audio to an
external WebSocket server and render whatever that server sends back into the
caller's codec. Against the control-plane mock (mock_siphon_rtp.py) that bridge
is never dialled, so nothing has ever proven audio actually traverses it. This
server is the other half of that test: it stands in for the inference backend
and asserts the media really arrived.

What it checks (see siphon-rtp docs/cookbook/voice-ai.md, "The WebSocket wire"):

  1. The first frame is a `start` envelope announcing the leg and audio format,
     and that format is the L16 shape the engine documents — little-endian,
     16-bit, mono, at the codec's native sample rate.
  2. Uplink binary frames arrive, one per ptime, each exactly
     sample_rate/1000 * ptime * 2 bytes (320 at 8 kHz / 20 ms).
  3. The uplink carries actual audio, not digital silence. This is the
     assertion that proves the whole path — SIPp's RTP, the engine's ingress
     gate, jitter buffer, and G.711 decode — rather than just proving a socket
     opened. A bridge that is up but passing zeros looks identical to a working
     one until you measure the samples.

Then it answers like an AI would: a short tone rendered as little-endian L16 at
the negotiated rate, which the engine re-encodes into the caller's codec. The
downlink is verified on the engine's own Prometheus counters rather than here,
since a server cannot observe what the far end received.

Every session prints one `AI-WS-VERDICT <json>` line. The CI step greps for it
and fails on `"pass": false` — a verdict that never appears is also a failure,
which is what catches the bridge never being dialled at all.
"""

import asyncio
import json
import math
import os
import struct
import sys

import websockets

LISTEN_HOST = os.environ.get("AI_WS_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("AI_WS_PORT", "9001"))

# Minimum uplink frames before the server talks back. At 20 ms/frame this is a
# fifth of a second of caller audio — enough to be sure the stream is flowing
# and not a single stray packet.
MIN_UPLINK_FRAMES = int(os.environ.get("AI_WS_MIN_FRAMES", "10"))

# Mean-square energy below which a frame counts as silence. G.711 decoded speech
# sits orders of magnitude above this; digital silence sits at exactly 0.
SILENCE_ENERGY = float(os.environ.get("AI_WS_SILENCE_ENERGY", "100"))

# Length of the synthesized "AI response" in frames (20 ms each).
RESPONSE_FRAMES = int(os.environ.get("AI_WS_RESPONSE_FRAMES", "25"))
RESPONSE_TONE_HZ = 440.0


def frame_energy(payload: bytes) -> float:
    """Mean-square energy of a little-endian 16-bit mono PCM frame."""
    count = len(payload) // 2
    if count == 0:
        return 0.0
    samples = struct.unpack(f"<{count}h", payload[: count * 2])
    return sum(sample * sample for sample in samples) / count


def tone_frame(sample_rate: int, samples_per_frame: int, phase: float) -> tuple[bytes, float]:
    """One frame of a 440 Hz sine, little-endian L16 — the AI's "voice"."""
    step = 2.0 * math.pi * RESPONSE_TONE_HZ / sample_rate
    values = []
    for index in range(samples_per_frame):
        values.append(int(8000 * math.sin(phase + step * index)))
    return struct.pack(f"<{samples_per_frame}h", *values), phase + step * samples_per_frame


class Session:
    """Assertion state for one bridged call."""

    def __init__(self) -> None:
        self.start_envelope: dict | None = None
        self.media: dict = {}
        self.uplink_frames = 0
        self.uplink_bytes = 0
        self.voiced_frames = 0
        self.peak_energy = 0.0
        self.bad_length_frames = 0
        self.downlink_frames = 0
        self.control_frames: list[str] = []
        self.failures: list[str] = []

    @property
    def sample_rate(self) -> int:
        return int(self.media.get("sampleRate", 8000))

    @property
    def ptime(self) -> int:
        return int(self.media.get("ptime", 20))

    @property
    def expected_frame_bytes(self) -> int:
        # little-endian L16 mono: two bytes per sample.
        return self.sample_rate // 1000 * self.ptime * 2

    def check_start(self, envelope: dict) -> None:
        self.start_envelope = envelope
        data = envelope.get("data", {})
        self.media = data.get("media", {})
        # The documented wire shape. A mismatch here means the engine changed the
        # contract the SDK and every integration is written against, so it is a
        # hard failure rather than something to tolerate.
        expected = {
            "encoding": "L16",
            "bitDepth": 16,
            "endianness": "little",
            "channels": 1,
        }
        for key, want in expected.items():
            got = self.media.get(key)
            if got != want:
                self.failures.append(f"start.media.{key}={got!r}, expected {want!r}")
        if not data.get("callId"):
            self.failures.append("start.data.callId missing")
        if not data.get("streamId"):
            self.failures.append("start.data.streamId missing")

    def check_uplink(self, payload: bytes) -> None:
        self.uplink_frames += 1
        self.uplink_bytes += len(payload)
        if len(payload) != self.expected_frame_bytes:
            self.bad_length_frames += 1
        energy = frame_energy(payload)
        self.peak_energy = max(self.peak_energy, energy)
        if energy > SILENCE_ENERGY:
            self.voiced_frames += 1

    def verdict(self) -> dict:
        failures = list(self.failures)
        if self.start_envelope is None:
            failures.append("no start envelope received")
        if self.uplink_frames < MIN_UPLINK_FRAMES:
            failures.append(
                f"only {self.uplink_frames} uplink frames, expected >= {MIN_UPLINK_FRAMES}"
            )
        if self.bad_length_frames:
            failures.append(
                f"{self.bad_length_frames} uplink frames were not "
                f"{self.expected_frame_bytes} bytes"
            )
        # The assertion that separates "a socket opened" from "audio arrived".
        if self.voiced_frames == 0:
            failures.append(
                f"every uplink frame was silence (peak mean-square energy "
                f"{self.peak_energy:.1f} <= {SILENCE_ENERGY})"
            )
        return {
            "pass": not failures,
            "failures": failures,
            "uplink_frames": self.uplink_frames,
            "uplink_bytes": self.uplink_bytes,
            "voiced_frames": self.voiced_frames,
            "peak_energy": round(self.peak_energy, 1),
            "downlink_frames": self.downlink_frames,
            "expected_frame_bytes": self.expected_frame_bytes,
            "control_frames": self.control_frames,
            "media": self.media,
        }


async def speak(connection, session: Session) -> None:
    """Send the synthesized AI response downlink, one frame per ptime tick."""
    samples_per_frame = session.sample_rate // 1000 * session.ptime
    phase = 0.0
    for _ in range(RESPONSE_FRAMES):
        payload, phase = tone_frame(session.sample_rate, samples_per_frame, phase)
        await connection.send(payload)
        session.downlink_frames += 1
        # Pace at the frame clock. The engine's downlink queue is bounded and
        # drop-oldest, so blasting the whole response at once would have most of
        # it discarded before playout.
        await asyncio.sleep(session.ptime / 1000.0)


async def handle(connection) -> None:
    session = Session()
    responder: asyncio.Task | None = None
    print(f"[ai-ws] session opened from {connection.remote_address}", flush=True)
    try:
        async for message in connection:
            if isinstance(message, bytes):
                session.check_uplink(message)
                # Once enough real caller audio has arrived, answer like an AI.
                if (
                    responder is None
                    and session.uplink_frames >= MIN_UPLINK_FRAMES
                    and session.voiced_frames > 0
                ):
                    responder = asyncio.create_task(speak(connection, session))
                continue
            try:
                envelope = json.loads(message)
            except ValueError:
                session.failures.append(f"non-JSON text frame: {message[:80]!r}")
                continue
            kind = envelope.get("type", "?")
            session.control_frames.append(kind)
            print(f"[ai-ws] control <- {json.dumps(envelope)}", flush=True)
            if kind == "start":
                session.check_start(envelope)
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if responder is not None:
            responder.cancel()
        verdict = session.verdict()
        print(f"AI-WS-VERDICT {json.dumps(verdict)}", flush=True)
        status = "PASS" if verdict["pass"] else "FAIL"
        print(
            f"[ai-ws] session closed: {status} "
            f"({verdict['uplink_frames']} up / {verdict['downlink_frames']} down, "
            f"{verdict['voiced_frames']} voiced)",
            flush=True,
        )


async def main() -> int:
    async with websockets.serve(handle, LISTEN_HOST, LISTEN_PORT, max_size=None):
        print(
            f"mock voice-AI WebSocket server listening on {LISTEN_HOST}:{LISTEN_PORT} "
            f"(min {MIN_UPLINK_FRAMES} uplink frames, {RESPONSE_FRAMES}-frame response)",
            flush=True,
        )
        await asyncio.Future()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(0)
