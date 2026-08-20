#!/usr/bin/env python3
"""Mock siphon-rtp native control server for functional testing.

Speaks the native JSON-over-TCP control protocol (a 4-byte big-endian length
prefix followed by a JSON body) so a SIPp scenario can exercise siphon's
media-anchoring path without building or running the real engine — the CI
analogue of sipp/rtpengine/mock_rtpengine.py, which does the same job for the
rtpengine NG/bencode protocol.

What it proves is the *composition*: that siphon identifies the carrier, issues
the right control verb with the right profile, and answers the call with the SDP
the engine handed back. It deliberately does not move audio.

The real engine covers the other half, and both halves are kept: this mock can
report what siphon *sent* (see the stdout echo below), which a real engine
cannot, while the real engine can reject what siphon sent and can move audio,
which this cannot. See the siphon-rtp-native / siphon-rtp-ng / voice-ai-real
compose profiles, which run the published engine image, and
sipp/siphon-rtp/mock_ai_ws.py, which asserts audio actually crosses the
WebSocket bridge.

For offer / answer / answer_local it returns SDP with the c-line rewritten to
MOCK_MEDIA_IP and the audio port to MOCK_MEDIA_PORT, simulating anchoring.

Every command received is echoed to stdout as one JSON line, so a scenario can
assert on what siphon actually sent — in particular that `profile.ws_uri` is
present and expanded.
"""

import json
import os
import re
import socket
import socketserver
import struct
import sys
import threading

LISTEN_HOST = os.environ.get("SIPHON_RTP_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("SIPHON_RTP_PORT", "8080"))
MOCK_MEDIA_IP = os.environ.get("MOCK_MEDIA_IP", "203.0.113.1")
MOCK_MEDIA_PORT = os.environ.get("MOCK_MEDIA_PORT", "30000")

HEADER = struct.Struct("!I")


def rewrite_sdp(sdp: str) -> str:
    """Point the SDP at the mock's media address, as an anchoring engine would."""
    sdp = re.sub(r"c=IN IP4 [\d.]+", f"c=IN IP4 {MOCK_MEDIA_IP}", sdp)
    sdp = re.sub(r"m=audio \d+", f"m=audio {MOCK_MEDIA_PORT}", sdp)
    return sdp


def answer_sdp_for(offer: str) -> str:
    """Synthesise a single-codec answer, the way answer_local does.

    RFC 3264 §6.1: the answer selects from the offered formats. Take the first
    offered payload type so the answer is consistent with the offer rather than
    inventing a codec the caller never proposed.
    """
    match = re.search(r"m=audio \d+ RTP/AVP ([\d ]+)", offer)
    payload = match.group(1).split()[0] if match else "0"
    rtpmap = re.search(rf"a=rtpmap:{payload} (\S+)", offer)
    codec = rtpmap.group(1) if rtpmap else "PCMU/8000"
    return (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {MOCK_MEDIA_IP}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {MOCK_MEDIA_IP}\r\n"
        "t=0 0\r\n"
        f"m=audio {MOCK_MEDIA_PORT} RTP/AVP {payload}\r\n"
        f"a=rtpmap:{payload} {codec}\r\n"
        "a=ptime:20\r\n"
    )


def handle_command(command: dict) -> dict:
    verb = command.get("command")
    if verb == "ping":
        return {"result": "pong"}
    if verb in ("offer", "answer"):
        return {"result": "ok", "sdp": rewrite_sdp(command.get("sdp", ""))}
    if verb == "answer_local":
        return {"result": "ok", "sdp": answer_sdp_for(command.get("sdp", ""))}
    if verb in ("delete", "attach_ws_tee", "detach_ws_tee", "play_media", "stop_media"):
        return {"result": "ok"}
    # Unknown verbs are an explicit error, never a silent ok — a mock that
    # answers ok to everything hides exactly the bugs this exists to catch.
    return {"result": "error", "reason": f"mock: unsupported verb {verb!r}"}


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        buffer = b""
        while True:
            try:
                chunk = self.request.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            buffer += chunk
            while len(buffer) >= HEADER.size:
                (length,) = HEADER.unpack(buffer[: HEADER.size])
                if len(buffer) < HEADER.size + length:
                    break
                body = buffer[HEADER.size : HEADER.size + length]
                buffer = buffer[HEADER.size + length :]
                try:
                    command = json.loads(body)
                except ValueError:
                    continue
                print(json.dumps(command), flush=True)
                response = handle_command(command)
                response["id"] = command.get("id", 0)
                payload = json.dumps(response).encode()
                try:
                    self.request.sendall(HEADER.pack(len(payload)) + payload)
                except OSError:
                    return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    with Server((LISTEN_HOST, LISTEN_PORT), Handler) as server:
        print(
            f"mock siphon-rtp control listening on {LISTEN_HOST}:{LISTEN_PORT} "
            f"(media {MOCK_MEDIA_IP}:{MOCK_MEDIA_PORT})",
            flush=True,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
