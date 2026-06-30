#!/usr/bin/env python3
"""Mock rtpproxy control server for functional testing.

Speaks the classic rtpproxy text protocol over UDP: each request is
``<cookie> <command>`` in a single datagram, and the reply is
``<cookie> <result>``.

Unlike rtpengine (which rewrites the SDP itself), rtpproxy only allocates a
relay port and returns ``<port> <address>`` — siphon rewrites the SDP. So this
mock just hands back a fixed ``MOCK_MEDIA_PORT MOCK_MEDIA_IP`` for every
create/lookup (``U``/``L``), a version for ``V``, and ``0`` for delete (``D``).
"""

import os
import socket

LISTEN_PORT = int(os.environ.get("RTPPROXY_PORT", "22222"))
MOCK_MEDIA_IP = os.environ.get("MOCK_MEDIA_IP", "203.0.113.1")
MOCK_MEDIA_PORT = os.environ.get("MOCK_MEDIA_PORT", "30000")
# Classic rtpproxy version token (an 8-digit date), returned for `V`.
VERSION = os.environ.get("RTPPROXY_VERSION", "20040107")


def handle_command(command: str) -> str:
    """Return the result string for a command (without the cookie)."""
    # The command letter is the first char; optional modifiers follow with no
    # separator (e.g. "Uie", "Lei"), then space-separated args.
    letter = command[:1].upper()
    if letter == "V":
        return VERSION
    if letter in ("U", "L"):
        # create/lookup → allocate a relay port + advertise the media address.
        return f"{MOCK_MEDIA_PORT} {MOCK_MEDIA_IP}"
    if letter == "D":
        return "0"
    # Q (info), I (info), X (delete-all), etc. — answer benignly.
    return "0"


def main() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    print(f"Mock rtpproxy listening on UDP port {LISTEN_PORT}", flush=True)
    print(f"  Media IP: {MOCK_MEDIA_IP}, Media port: {MOCK_MEDIA_PORT}", flush=True)

    while True:
        data, address = sock.recvfrom(65535)
        cookie = b""
        try:
            # Protocol: "<cookie> <command>"
            space_index = data.index(b" ")
            cookie = data[:space_index]
            command = data[space_index + 1:].decode(errors="replace").strip()
            letter = command[:1].upper() if command else "?"
            print(f"[{address[0]}:{address[1]}] {letter} :: {command}", flush=True)

            result = handle_command(command)
            reply = cookie + b" " + result.encode()
            sock.sendto(reply, address)
        except Exception as error:  # noqa: BLE001 — best-effort mock
            print(f"Error processing request from {address}: {error}", flush=True)
            try:
                sock.sendto(cookie + b" E1", address)
            except Exception:
                pass


if __name__ == "__main__":
    main()
