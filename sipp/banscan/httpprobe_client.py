"""Non-SIP probe regression client (the vulnerability-scanner pattern).

Phase 1: a complete HTTP request on the TCP SIP port must be closed without an
answer. Framing alone cannot reject it — an HTTP header block ends in the same
\\r\\n\\r\\n a SIP message does and carries no Content-Length — so a build that
classifies only *incomplete* frames queues the probe to the dispatcher, logs it,
and leaves the connection open.
Phase 2: that one probe is a strong auto-ban signal (weight 3 against this
config's threshold of 3), so the next connection from the same IP must be
dropped at accept, before any SIP parsing. A build that never records the probe
answers the REGISTER with a 401 -> exit 1.

exit 0 = probe dropped and source banned, 1 = regression, 2 = setup error.
"""
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 5060

PROBE = (
    b"GET /phpinfo.php HTTP/1.1\r\n"
    b"Host: 127.0.0.1\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"\r\n"
)

REGISTER = (
    f"REGISTER sip:{HOST} SIP/2.0\r\n"
    f"Via: SIP/2.0/TCP {HOST}:7000;branch=z9hG4bK-probe-99\r\n"
    f"From: <sip:scanner@{HOST}>;tag=probe99\r\n"
    f"To: <sip:scanner@{HOST}>\r\n"
    f"Call-ID: probe-99@{HOST}\r\n"
    f"CSeq: 99 REGISTER\r\n"
    f"Max-Forwards: 70\r\n"
    f"Content-Length: 0\r\n\r\n"
).encode()

# Phase 1 — the probe is closed, never answered.
try:
    conn = socket.create_connection((HOST, PORT), timeout=5)
    conn.settimeout(5)
    conn.sendall(PROBE)
    try:
        data = conn.recv(4096)
    except socket.timeout:
        print("phase1: probe neither answered nor closed -> connection held open", flush=True)
        sys.exit(1)
    finally:
        conn.close()
except ConnectionRefusedError as error:
    print(f"phase1: siphon not reachable ({error})", flush=True)
    sys.exit(2)

if data:
    first = data.split(b"\r\n", 1)[0].decode(errors="replace")
    print(f"phase1: probe was ANSWERED (fingerprints the port): {first}", flush=True)
    sys.exit(1)
print("phase1: probe closed without a response (pass)", flush=True)

time.sleep(1)  # let the ban settle

# Phase 2 — the probe counted, so the source is banned at accept.
try:
    conn = socket.create_connection((HOST, PORT), timeout=5)
    conn.settimeout(5)
    conn.sendall(REGISTER)
    try:
        data = conn.recv(4096)
    except socket.timeout:
        print("phase2: no response within timeout -> BANNED (pass)", flush=True)
        sys.exit(0)
    finally:
        conn.close()
except (ConnectionRefusedError, ConnectionResetError) as error:
    print(f"phase2: connection refused/reset ({error}) -> BANNED (pass)", flush=True)
    sys.exit(0)

if not data:
    print("phase2: connection closed without a response -> BANNED (pass)", flush=True)
    sys.exit(0)
first = data.split(b"\r\n", 1)[0].decode(errors="replace")
print(f"phase2: got a response (probe was never counted): {first}", flush=True)
sys.exit(1)
