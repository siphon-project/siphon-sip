"""failed_auth_ban regression client.

Phase 1: send unauthenticated REGISTERs on one connection — each draws a 401,
which records a failure. After `threshold` (3) the source IP is banned.
Phase 2: a FRESH connection from the same IP must be dropped at accept (banned
before any SIP parsing) — no 401 comes back. Healthy-but-unbanned would answer
401 → test fails.

exit 0 = banned as expected, 1 = not banned (regression), 2 = setup error.
"""
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 5060


def register(conn, index):
    conn.sendall(
        (
            f"REGISTER sip:{HOST} SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP {HOST}:7000;branch=z9hG4bK-ban-{index}\r\n"
            f"From: <sip:scanner@{HOST}>;tag=ban{index}\r\n"
            f"To: <sip:scanner@{HOST}>\r\n"
            f"Call-ID: ban-{index}@{HOST}\r\n"
            f"CSeq: {index} REGISTER\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
    )


# Phase 1 — trip the ban (threshold 3; send 5 to be safe).
challenges = 0
conn1 = socket.create_connection((HOST, PORT), timeout=5)
conn1.settimeout(5)
for index in range(1, 6):
    register(conn1, index)
    try:
        data = conn1.recv(4096)
        if b" 401 " in data:
            challenges += 1
    except socket.timeout:
        break
conn1.close()
print(f"phase1: {challenges} challenges received (ban trips at 3)", flush=True)
if challenges < 3:
    print("phase1: fewer than 3 challenges — setup broken, can't trip the ban", flush=True)
    sys.exit(2)

time.sleep(1)  # let the ban settle

# Phase 2 — a fresh connection from the same IP must be banned at accept.
try:
    conn2 = socket.create_connection((HOST, PORT), timeout=5)
    conn2.settimeout(5)
    register(conn2, 99)
    try:
        data = conn2.recv(4096)
        if not data:
            print("phase2: connection closed without a response -> BANNED (pass)", flush=True)
            sys.exit(0)
        first = data.split(b"\r\n", 1)[0].decode(errors="replace")
        print(f"phase2: got a response (NOT banned): {first}", flush=True)
        sys.exit(1)
    except socket.timeout:
        print("phase2: no response within timeout -> BANNED (pass)", flush=True)
        sys.exit(0)
except (ConnectionRefusedError, ConnectionResetError) as error:
    print(f"phase2: connection refused/reset ({error}) -> BANNED (pass)", flush=True)
    sys.exit(0)
