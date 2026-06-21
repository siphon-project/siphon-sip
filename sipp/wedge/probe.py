"""Probe for the outbound-drain wedge regression.

A fresh connection sends one OPTIONS and expects a 200 within a timeout. On a
wedged siphon (the single outbound distributor stalled by the non-reading peer)
the response never arrives -> timeout -> exit 1 (test FAIL). On a healthy build
the distributor sheds the stuck peer and answers us -> exit 0 (test PASS).

Usage: probe.py [host] [port] [timeout_secs]
"""
import socket
import sys

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5060
timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0

try:
    sock = socket.create_connection((host, port), timeout=5)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(
        (
            f"OPTIONS sip:{host} SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {host}:6001;branch=z9hG4bK-probe-1\r\n"
            f"From: <sip:probe@{host}>;tag=probe1\r\n"
            f"To: <sip:{host}>\r\n"
            f"Call-ID: probe-1@{host}\r\n"
            f"CSeq: 1 OPTIONS\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
    )
    sock.settimeout(timeout)
    data = sock.recv(4096)
    if data:
        print("probe: GOT RESPONSE ->", data.split(b"\r\n", 1)[0].decode(errors="replace"), flush=True)
        sys.exit(0)
    print("probe: connection closed without a response (WEDGED)", flush=True)
    sys.exit(1)
except socket.timeout:
    print(f"probe: TIMEOUT — no response within {timeout}s (WEDGED)", flush=True)
    sys.exit(1)
except Exception as error:
    print("probe: error:", error, flush=True)
    sys.exit(2)
