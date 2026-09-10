"""Rejected-WebSocket-upgrade auto-ban regression client.

A peer that completes the transport handshake on a SIP-over-WebSocket port and
then sends an HTTP request that is *not* an upgrade is a scanner: RFC 7118 §5
leaves a conforming client no way to produce one. That scores
`strong_signal_weight` (3), so a single probe crosses this config's threshold
of 3.

Phase 1: send a bare `GET /` (no Connection/Upgrade headers) on the ws port.
         The upgrade is rejected and the connection closed without a 101.
Phase 2: a FRESH connection from the same IP must be dropped at accept — the
         one probe was enough. If a second probe is still answered, the signal
         is being scored as a weak handshake failure again (weight 1) and the
         ban needs three probes instead of one.

exit 0 = banned after one probe, 1 = not banned (regression), 2 = setup error.
"""

import socket
import sys
import time

HOST, PORT = "127.0.0.1", 5562


def probe(index):
    """One non-upgrade HTTP request. Returns the bytes the server sent back."""
    connection = socket.create_connection((HOST, PORT), timeout=5)
    connection.settimeout(5)
    try:
        connection.sendall(
            (
                f"GET /probe{index} HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\n"
                f"User-Agent: probe\r\n"
                f"\r\n"
            ).encode()
        )
        try:
            return connection.recv(4096)
        except socket.timeout:
            return b""
    finally:
        connection.close()


# Phase 1 — one rejected upgrade must be enough at strong weight.
try:
    first = probe(1)
except OSError as error:
    print(f"phase1: could not connect to the ws listener: {error}", flush=True)
    sys.exit(2)

if b" 101 " in first:
    print("phase1: server accepted the upgrade — probe was not rejected", flush=True)
    sys.exit(2)
print(f"phase1: non-upgrade probe rejected ({len(first)} bytes back)", flush=True)

time.sleep(1)  # let the ban settle

# Phase 2 — a fresh connection from the same IP must now be dropped at accept.
try:
    second = probe(2)
except (ConnectionRefusedError, ConnectionResetError):
    print("phase2: connection refused/reset — banned", flush=True)
    sys.exit(0)
except OSError as error:
    print(f"phase2: connection failed ({error}) — treating as banned", flush=True)
    sys.exit(0)

if not second:
    print("phase2: no response — banned at accept", flush=True)
    sys.exit(0)

print(f"phase2: got a response (NOT banned): {second[:40]!r}", flush=True)
print(
    "phase2: a rejected upgrade is scoring as a weak signal — it must carry "
    "strong_signal_weight",
    flush=True,
)
sys.exit(1)
