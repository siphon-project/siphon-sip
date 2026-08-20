#!/usr/bin/env python3
"""Mock siphon-rtp native control server for functional testing.

Speaks the native JSON-over-TCP control protocol (a 4-byte big-endian length
prefix followed by a JSON body) so a SIPp scenario can exercise siphon's
media-anchoring path without building or running the real engine — the CI
analogue of sipp/rtpengine/mock_rtpengine.py, which does the same job for the
rtpengine NG/bencode protocol.

What it proves is the *composition*: that siphon identifies the carrier, issues
the right control verb with the right profile, and answers the call with the SDP
the engine handed back. It deliberately does not move audio. Proving the audio
path needs the real engine plus a WebSocket media server; that run is gated on
SIPHON_RTP_BIN (see tests/integration/siphon_rtp_tests.rs) because CI does not
build the engine.

For offer / answer / answer_local it returns SDP with the c-line rewritten to
MOCK_MEDIA_IP and the audio port to the one allocated for that call, simulating
anchoring.

Port allocation models the real engine's distinction between the two ways an SDP
offer can arrive on a live call, which is the whole reason `reoffer` exists:

  * `offer` on a NEW call-id allocates a port.
  * `offer` on a LIVE call-id is a REPLACEMENT — the old call is freed and a
    NEW port allocated, so a caller is handed an address it was never told
    about and everything attached to the old ports is gone.
  * `reoffer` on a live call-id renegotiates in place and returns the SAME
    port. On an unknown call-id it is an error, never an implicit create.

A test therefore sees a regression twice over: in the verb the mock logs, and in
the media port the caller is answered with.

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


def rewrite_sdp(sdp: str, port: int) -> str:
    """Point the SDP at the mock's media address and this call's allocated port."""
    sdp = re.sub(r"c=IN IP4 [\d.]+", f"c=IN IP4 {MOCK_MEDIA_IP}", sdp)
    sdp = re.sub(r"m=audio \d+", f"m=audio {port}", sdp)
    return sdp


def answer_sdp_for(offer: str, port: int) -> str:
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
        f"m=audio {port} RTP/AVP {payload}\r\n"
        f"a=rtpmap:{payload} {codec}\r\n"
        "a=ptime:20\r\n"
    )


# call-id -> {"port": int, "codec": str}. Guarded by `CALLS_LOCK` because the
# server is threaded (one thread per control connection).
CALLS: dict = {}
CALLS_LOCK = threading.Lock()
NEXT_PORT = [int(MOCK_MEDIA_PORT)]


def allocate_port() -> int:
    """Hand out the next even media port, as an engine allocating a pair does."""
    port = NEXT_PORT[0]
    NEXT_PORT[0] += 2
    return port


def primary_codec(sdp: str) -> str:
    """The first codec name in the offer, for the codec-change refusal below."""
    match = re.search(r"m=audio \d+ RTP/AVP ([\d ]+)", sdp)
    payload = match.group(1).split()[0] if match else "0"
    rtpmap = re.search(rf"a=rtpmap:{payload} ([^/\s]+)", sdp)
    return rtpmap.group(1).upper() if rtpmap else f"PT{payload}"


def handle_command(command: dict) -> dict:
    verb = command.get("command")
    call_id = command.get("call_id", "")
    if verb == "ping":
        return {"result": "pong"}
    if verb == "offer":
        sdp = command.get("sdp", "")
        with CALLS_LOCK:
            # A repeat offer on a live call-id is a replacement: fresh ports, and
            # whatever was attached to the old ones is gone.
            port = allocate_port()
            CALLS[call_id] = {"port": port, "codec": primary_codec(sdp)}
        return {"result": "ok", "sdp": rewrite_sdp(sdp, port)}
    if verb == "reoffer":
        sdp = command.get("sdp", "")
        with CALLS_LOCK:
            call = CALLS.get(call_id)
            if call is None:
                # Never an implicit create — that would hide the very bug a
                # re-offer addressed to the wrong call-id causes.
                return {"result": "error", "reason": f"unknown call-id {call_id!r}"}
            offered = primary_codec(sdp)
            if offered != call["codec"]:
                # The real engine refuses this: changing the negotiated codec
                # needs a pipeline rebuild it will not do on a live call.
                return {
                    "result": "error",
                    "reason": (
                        f"re-offer changes the negotiated codec ({call['codec']} -> {offered}); "
                        "not supported on a live call - replace it with a fresh offer instead"
                    ),
                }
            port = call["port"]
        return {"result": "ok", "sdp": rewrite_sdp(sdp, port)}
    if verb == "answer":
        with CALLS_LOCK:
            call = CALLS.get(call_id)
            port = call["port"] if call else allocate_port()
        return {"result": "ok", "sdp": rewrite_sdp(command.get("sdp", ""), port)}
    if verb == "answer_local":
        with CALLS_LOCK:
            port = allocate_port()
            CALLS[call_id] = {"port": port, "codec": primary_codec(command.get("sdp", ""))}
        return {"result": "ok", "sdp": answer_sdp_for(command.get("sdp", ""), port)}
    if verb == "delete":
        with CALLS_LOCK:
            CALLS.pop(call_id, None)
        return {"result": "ok"}
    if verb in ("attach_ws_tee", "detach_ws_tee", "play_media", "stop_media"):
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
