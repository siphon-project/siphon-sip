"""failed_auth_ban regression client.

Phase 1: send unauthenticated REGISTERs on one connection — each draws a 401,
which records a failure. At `threshold` (3) the source IP is banned, and the
connection it is holding is closed with it. That close is half the point of the
phase: every other ban check runs once per connection (the ACL at accept, the
re-check after a handshake), so a client that never reconnects used to keep this
connection and go on presenting rejected credentials on it for the whole ban,
while every other client behind the same address was refused at accept.
Phase 2: a FRESH connection from the same IP must be dropped at accept (banned
before any SIP parsing) — no 401 comes back. Healthy-but-unbanned would answer
401 → test fails.

exit 0 = banned and disconnected as expected, 1 = regression, 2 = setup error.
"""
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 5560
# security.failed_auth_ban.threshold in siphon-banscan.yaml, at
# missing_credentials_weight 1 — so one REGISTER per count.
THRESHOLD = 3

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

def read(conn):
    """One read: bytes, b"" for a connection that has ended, None for silence."""
    try:
        return conn.recv(4096)
    except (ConnectionResetError, BrokenPipeError):
        return b""
    except socket.timeout:
        return None

conn1 = socket.create_connection((HOST, PORT), timeout=5)
conn1.settimeout(5)

# The counts before the last one: each draws a 401 and the connection stays up.
challenges = 0
for index in range(1, THRESHOLD):
    register(conn1, index)
    data = read(conn1)
    if not data:
        print(
            f"phase1: connection ended after {index} REGISTER(s), before the "
            f"threshold of {THRESHOLD} — setup broken",
            flush=True,
        )
        sys.exit(2)
    if b" 401 " in data:
        challenges += 1
if challenges != THRESHOLD - 1:
    print(
        f"phase1: {challenges} challenges before the threshold, expected "
        f"{THRESHOLD - 1} — setup broken, can't trip the ban",
        flush=True,
    )
    sys.exit(2)
print(f"phase1: {challenges} challenges on one connection, ban trips on the next", flush=True)

# The REGISTER that trips the ban. Whether its own 401 gets out ahead of the
# teardown is a race, and not what this asserts: the connection must END.
try:
    register(conn1, THRESHOLD)
except (ConnectionResetError, BrokenPipeError):
    print("phase1: the connection was already gone -> CLOSED (pass)", flush=True)
else:
    deadline = time.monotonic() + 10
    while True:
        if read(conn1) == b"":
            print("phase1: the connection the scanner held was closed (pass)", flush=True)
            break
        if time.monotonic() > deadline:
            print(
                "phase1: the connection stayed open after the ban — the scanner "
                "keeps the one connection nothing re-checks (REGRESSION)",
                flush=True,
            )
            sys.exit(1)
conn1.close()

time.sleep(1)  # let the ban settle

try:
    conn2 = socket.create_connection((HOST, PORT), timeout=5)
    conn2.settimeout(5)
    register(conn2, 99)
    data = read(conn2)
    if not data:
        print("phase2: connection closed without a response -> BANNED (pass)", flush=True)
        sys.exit(0)
    if data is None:
        print("phase2: no response within timeout -> BANNED (pass)", flush=True)
        sys.exit(0)
    first = data.split(b"\r\n", 1)[0].decode(errors="replace")
    print(f"phase2: got a response (NOT banned): {first}", flush=True)
    sys.exit(1)
except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError) as error:
    print(f"phase2: connection refused/reset ({error}) -> BANNED (pass)", flush=True)
    sys.exit(0)
