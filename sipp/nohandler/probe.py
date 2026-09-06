"""Wire assertions for the no-script-handler fallback.

Usage: probe.py [on|off|wait]  (on/off match server.auto_options in the
                                running siphon; wait blocks until it answers)

    on   OPTIONS -> 200 with Allow + Contact           RFC 3261 s11.2
         same branch resent -> 200 again, from the server transaction's cached
         response rather than a re-run                 RFC 3261 s17.2.2
    off  OPTIONS -> nothing at all, and no synthesized 100 Trying either

Both modes assert an unhandled MESSAGE and INVITE still get 405 + Allow
(RFC 3261 s8.2.1) -- the knob is scoped to OPTIONS and must not silence those.

Exits non-zero with a description of every assertion that failed.
"""
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 15080
SOURCE_PORT = 15099
failures = []


def send(method, branch, timeout=6):
    """Send one request; return the response text, or None on timeout."""
    raw = (
        f"{method} sip:probe@{HOST} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {HOST}:{SOURCE_PORT};branch={branch}\r\n"
        f"From: <sip:probe@peer.invalid>;tag=probe\r\n"
        f"To: <sip:probe@{HOST}>\r\n"
        f"Call-ID: nohandler-{branch}\r\n"
        f"CSeq: 1 {method}\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Length: 0\r\n"
        f"\r\n"
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, SOURCE_PORT))
    # The default is comfortably past the RFC 4320 s4.2 auto-100 window (~3.5s
    # over UDP), so "no response" in the off mode really means no response --
    # not a 100 that simply had not fired yet.
    sock.settimeout(timeout)
    try:
        sock.sendto(raw.encode(), (HOST, PORT))
        return sock.recv(4096).decode(errors="replace")
    except socket.timeout:
        return None
    finally:
        sock.close()


def status_of(response):
    return response.splitlines()[0] if response else None


def expect(label, response, code, headers=()):
    line = status_of(response)
    if line is None:
        failures.append(f"{label}: expected {code}, got no response")
        return
    if f" {code} " not in line + " ":
        failures.append(f"{label}: expected {code}, got {line!r}")
        return
    lowered = "\n" + response.lower()
    for header in headers:
        if f"\n{header.lower()}:" not in lowered:
            failures.append(f"{label}: {code} is missing the {header} header")
            return
    print(f"  PASS {label}: {line}")


def expect_silence(label, response):
    line = status_of(response)
    if line is None:
        print(f"  PASS {label}: no response")
    else:
        failures.append(f"{label}: expected silence, got {line!r}")


mode = sys.argv[1] if len(sys.argv) > 1 else "on"

if mode == "wait":
    # Readiness. It has to be a real SIP round-trip: a UDP connect() sets the
    # peer without sending anything, so it "succeeds" against a port nothing is
    # bound to and would hand the first real probe a dropped datagram. MESSAGE
    # is the request to ask with -- it draws a 405 in BOTH modes, where OPTIONS
    # is deliberately silent in one of them.
    deadline = time.monotonic() + 30
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        response = send("MESSAGE", f"z9hG4bK-ready-{attempt}", timeout=1)
        if response is not None:
            sys.exit(0)
    print("FAIL: siphon did not answer within 30s")
    sys.exit(1)

if mode == "on":
    # RFC 3261 s11.2 -- a capability response, which needs the Contact too:
    # some peers reject an OPTIONS answer carrying neither Contact nor
    # Record-Route.
    expect("OPTIONS", send("OPTIONS", "z9hG4bK-opt"), 200, ("Allow", "Contact"))
    # RFC 3261 s17.2.2 -- the response is fed to the server transaction, so a
    # retransmission (the lost-probe case over UDP) is answered from cache. If
    # it were sent straight to the socket instead, the NIST would sit in Trying
    # with nothing to replay and this second probe would time out.
    branch = "z9hG4bK-optretx"
    expect("OPTIONS first", send("OPTIONS", branch), 200, ("Allow",))
    expect("OPTIONS retransmit", send("OPTIONS", branch), 200, ("Allow",))
else:
    # The drop has to reap the server transaction and its auto-100 timer, or
    # RFC 4320 s4.2's synthesized 100 Trying goes out anyway -- which strands
    # the transaction AND tells a scanner something is listening, the one thing
    # turning this off was meant to prevent.
    expect_silence("OPTIONS", send("OPTIONS", "z9hG4bK-optoff"))

expect("MESSAGE", send("MESSAGE", "z9hG4bK-msg"), 405, ("Allow",))
expect("INVITE", send("INVITE", "z9hG4bK-inv"), 405, ("Allow",))

if failures:
    print(f"\nFAIL ({mode}):")
    for failure in failures:
        print(f"  - {failure}")
    sys.exit(1)
print(f"\nPASS: no-handler fallback correct with auto_options {mode}")
