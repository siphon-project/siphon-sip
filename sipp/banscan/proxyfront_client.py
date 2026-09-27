"""Auto-ban regression for traffic arriving behind a PROXY-protocol front.

The bug this guards: with a connection-terminating front, every request looks
like it came from the front, so the auto-ban store bans the FRONT. One abuser
then takes out every subscriber behind that load balancer, and the abuser keeps
going.

Phase 1: open one connection to the proxy_protocol listener, assert a v1 header
claiming an abuser address, then send unauthenticated REGISTERs. Each draws a
401, which records a failure against whichever address siphon attributed the
request to. At the threshold (3) that address is banned and the connection it
holds is closed — which behind a front is only possible if the connection is
matched by the address the header declared, not by the front's own.

Phase 2: read GET /admin/bans and require BOTH halves — the abuser is banned,
and the front is not. A build where the substitution never reaches the auth path
bans 127.0.0.1 (this client, which is the front here) and leaves the abuser
free, which is the failure inverted.

exit 0 = the abuser was banned and the front was not, 1 = regression,
2 = setup error.
"""
import json
import socket
import sys
import time
import urllib.error
import urllib.request

HOST, PORT = "127.0.0.1", 5564
ADMIN = "http://127.0.0.1:5565/admin/bans"
# security.failed_auth_ban.threshold in siphon-banscan.yaml, at
# missing_credentials_weight 1 — so one REGISTER per count.
THRESHOLD = 3

# The abuser the header claims. The front is this client, on loopback.
ABUSER = "203.0.113.9"
FRONT = "127.0.0.1"

PROXY_HEADER = f"PROXY TCP4 {ABUSER} 192.0.2.1 51234 {PORT}\r\n".encode()


def register(conn, index):
    conn.sendall(
        (
            f"REGISTER sip:{FRONT} SIP/2.0\r\n"
            f"Via: SIP/2.0/TCP 10.0.0.5:7000;branch=z9hG4bK-front-{index}\r\n"
            f"From: <sip:scanner@{FRONT}>;tag=front{index}\r\n"
            f"To: <sip:scanner@{FRONT}>\r\n"
            f"Call-ID: front-{index}@{FRONT}\r\n"
            f"CSeq: {index} REGISTER\r\n"
            f"Max-Forwards: 70\r\n"
            f"Content-Length: 0\r\n\r\n"
        ).encode()
    )


# Phase 1 — the front asserts the abuser's address, then the abuser misbehaves.
challenges = 0
try:
    conn = socket.create_connection((HOST, PORT), timeout=5)
except OSError as error:
    print(f"phase1: proxy_protocol listener not reachable ({error})", flush=True)
    sys.exit(2)

conn.settimeout(5)
conn.sendall(PROXY_HEADER)


def read(connection):
    """One read: bytes, b"" for a connection that has ended, None for silence."""
    try:
        return connection.recv(4096)
    except (ConnectionResetError, BrokenPipeError):
        return b""
    except socket.timeout:
        return None


# The counts before the last one: each draws a 401 and the connection stays up.
for index in range(1, THRESHOLD):
    register(conn, index)
    data = read(conn)
    if not data:
        print(
            f"phase1: connection ended after {index} REGISTER(s), before the "
            f"threshold of {THRESHOLD} — setup broken",
            flush=True,
        )
        sys.exit(2)
    if b" 401 " in data:
        challenges += 1

print(f"phase1: {challenges} challenges received (ban trips at {THRESHOLD})", flush=True)
if challenges != THRESHOLD - 1:
    print(
        f"phase1: {challenges} challenges before the threshold, expected "
        f"{THRESHOLD - 1} — the header was rejected or the listener is "
        "misconfigured, so the ban cannot be tripped",
        flush=True,
    )
    sys.exit(2)

# The REGISTER that trips the ban closes the connection carrying it. Whether its
# own 401 gets out ahead of the teardown is a race and not what this asserts.
try:
    register(conn, THRESHOLD)
except (ConnectionResetError, BrokenPipeError):
    print("phase1: the connection was already gone -> CLOSED (pass)", flush=True)
else:
    deadline = time.monotonic() + 10
    while True:
        if read(conn) == b"":
            print(
                f"phase1: the connection carrying {ABUSER} was closed (pass)",
                flush=True,
            )
            break
        if time.monotonic() > deadline:
            print(
                "phase1: the connection stayed open after the ban — behind a "
                "front the abuser keeps the one connection nothing re-checks "
                "(REGRESSION)",
                flush=True,
            )
            sys.exit(1)
conn.close()

time.sleep(1)  # let the ban settle

# Phase 2 — the ban store has to name the abuser, not the front.
try:
    with urllib.request.urlopen(ADMIN, timeout=5) as response:
        bans = json.load(response)
except (urllib.error.URLError, OSError, ValueError) as error:
    print(f"phase2: admin API unreachable ({error})", flush=True)
    sys.exit(2)

banned = {entry.get("ip") for entry in bans}
print(f"phase2: banned sources = {sorted(banned)}", flush=True)

if FRONT in banned:
    print(
        f"phase2: the FRONT ({FRONT}) was banned — one abuser just took out "
        "every client behind the load balancer",
        flush=True,
    )
    sys.exit(1)

if ABUSER not in banned:
    print(
        f"phase2: the abuser ({ABUSER}) was NOT banned — the auth path never "
        "saw the client's address, so auto-ban is blind behind a front",
        flush=True,
    )
    sys.exit(1)

print(f"phase2: {ABUSER} banned, {FRONT} untouched (pass)", flush=True)
sys.exit(0)
