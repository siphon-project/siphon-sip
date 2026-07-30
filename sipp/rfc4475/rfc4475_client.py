"""RFC 4475 on-the-wire regression client.

Runs against a siphon container (scripts/rfc4475_test.sh) whose script answers
200 to anything that reaches it.

`tests/rfc4475/corpus_tests.rs` proves the *decision* — that each of the 50
torture messages is accepted or refused as RFC 4475 requires. It cannot prove
the consequence: that a refusal actually reaches the peer. A validation layer
that returns the right `Rejection` but is never wired to a socket looks
identical to one that is, from inside a unit test. This closes that gap by
putting the byte-exact fixtures on a real UDP socket and reading what comes
back.

Three outcomes are distinguished:

  * accepted        -> reached the script, which answers 200
  * refused with N  -> the validation layer named status N and the dispatcher
                       sent it (400 Bad Request, or 505 Version Not Supported)
  * dropped         -> the parser could not represent the message at all, so
                       there is nothing to answer and no response is sent

The fixtures are sent verbatim, byte for byte, with no Via rewriting: siphon
routes responses to the observed source address rather than the Via sent-by, so
a reply to a message whose Via names 192.0.2.2 still comes back here.

exit 0 = all checks pass, 1 = a regression, 2 = setup error.
"""
import pathlib
import socket
import sys

DST = ("127.0.0.1", 5060)
CORPUS = pathlib.Path(__file__).resolve().parents[2] / "tests" / "rfc4475" / "corpus"
TIMEOUT_SECS = 2.0

# Must be accepted and reach the script. Each of these failed to parse before
# the grammar fixes, so a 200 here is the wire-level proof of that fix.
ACCEPTED = {
    "TC_WSINV.dat": "§3.1.1.1 whitespace before HCOLON (`TO :`), folded headers",
    "TC_INTMETH.dat": "§3.1.1.2 extension-method over the full token charset",
    "TC_ESC02_V.dat": "§3.1.1.5 method `RE%47IST%45R` — % is not an escape",
    "TC_LONGREQ_V.dat": "§3.1.1.7 `v :` / `V  :` / `Via  :` across 23 Via headers",
    "TC_UNKSCM_V.dat": "§3.3.2 absoluteURI Request-URI, unknown scheme",
    "TC_NOVELSC_V.dat": "§3.3.3 absoluteURI Request-URI, `soap.beep:`",
}

# Must be refused with exactly this status, sent back to us.
REFUSED = {
    "TC_BADVERS_V.dat": (505, "§3.1.2.16 SIP/7.0"),
    "TC_MISMATCH01_V.dat": (400, "§3.1.2.17 CSeq method != Request-Line method"),
    "TC_MISMATCH02_V.dat": (400, "§3.1.2.18 unknown method + CSeq mismatch"),
    "TC_SCALAR02_V.dat": (400, "§3.1.2.4 CSeq sequence number >= 2**31"),
    "TC_BADDATE_V.dat": (400, "§3.1.2.12 Date time zone is not GMT"),
    "TC_ESCRURI_V.dat": (400, "§3.1.2.11 escaped headers in the Request-URI"),
    "TC_QUOTBAL_I.dat": (400, "§3.1.2.6 unterminated quoted display name"),
    "TC_BADASPEC_I.dat": (400, "§3.1.2.14 whitespace inside <>"),
    "TC_REGBADCT_I.dat": (400, "§3.1.2.13 bare addr-spec carrying '?'"),
    "TC_BADINV01_I.dat": (400, "§3.1.2.1 empty header field parameters"),
}

# Must draw no response at all.
DROPPED = {
    "TC_CLERR_I.dat": "§3.1.2.2 Content-Length overruns the datagram",
    "TC_NCL_I.dat": "§3.1.2.3 negative Content-Length",
    "TC_LWSSTART_V.dat": "§3.1.2.9 multiple SP in the Request-Line",
    "TC_SCALARLG_V.dat": "§3.1.2.5 invalid response — nothing to answer",
}

CONTROL = (
    "OPTIONS sip:ping@127.0.0.1 SIP/2.0\r\n"
    "Via: SIP/2.0/UDP 127.0.0.1:6099;branch=z9hG4bK-rfc4475-control\r\n"
    "From: <sip:probe@127.0.0.1>;tag=control\r\n"
    "To: <sip:ping@127.0.0.1>\r\n"
    "Call-ID: rfc4475-control@127.0.0.1\r\n"
    "CSeq: 1 OPTIONS\r\n"
    "Max-Forwards: 70\r\n"
    "Content-Length: 0\r\n\r\n"
).encode()


def exchange(payload):
    """Send `payload` from a fresh socket; return the status code, or None."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_SECS)
        sock.sendto(payload, DST)
        try:
            data = sock.recv(65535)
        except socket.timeout:
            return None
    if not data.startswith(b"SIP/2.0 "):
        return None
    try:
        return int(data[8:11])
    except ValueError:
        return None


def fixture(name):
    path = CORPUS / name
    if not path.is_file():
        print(f"setup error: fixture {name} not found at {path}", flush=True)
        sys.exit(2)
    return path.read_bytes()


if not CORPUS.is_dir():
    print(f"setup error: corpus directory not found at {CORPUS}", flush=True)
    sys.exit(2)

# ── Control — prove the harness is live before reading anything into silence ──
if exchange(CONTROL) != 200:
    print(
        "setup error: a well-formed OPTIONS got no 200 — siphon or the handler "
        "is not up, so a silent fixture would be indistinguishable from a drop",
        flush=True,
    )
    sys.exit(2)
print("control: well-formed OPTIONS answered 200 -> harness live", flush=True)

failures = []

# ── Accepted ─────────────────────────────────────────────────────────────────
for name, why in sorted(ACCEPTED.items()):
    status = exchange(fixture(name))
    if status == 200:
        print(f"accept  {name:<22} 200  ({why})", flush=True)
    else:
        seen = "silence" if status is None else str(status)
        print(f"FAIL    {name:<22} expected 200, got {seen}  ({why})", flush=True)
        failures.append(name)

# ── Refused with a specific status ───────────────────────────────────────────
for name, (expected, why) in sorted(REFUSED.items()):
    status = exchange(fixture(name))
    if status == expected:
        print(f"refuse  {name:<22} {expected}  ({why})", flush=True)
    else:
        seen = "silence" if status is None else str(status)
        print(
            f"FAIL    {name:<22} expected {expected}, got {seen}  ({why})",
            flush=True,
        )
        failures.append(name)

# ── Dropped ──────────────────────────────────────────────────────────────────
for name, why in sorted(DROPPED.items()):
    status = exchange(fixture(name))
    if status is None:
        print(f"drop    {name:<22} silence  ({why})", flush=True)
    else:
        print(f"FAIL    {name:<22} expected silence, got {status}  ({why})", flush=True)
        failures.append(name)

total = len(ACCEPTED) + len(REFUSED) + len(DROPPED)
if failures:
    print(
        f"\n{len(failures)} of {total} fixtures behaved wrongly on the wire: "
        f"{', '.join(sorted(failures))}",
        flush=True,
    )
    sys.exit(1)

print(f"\nALL {total} FIXTURES BEHAVE AS RFC 4475 REQUIRES ON THE WIRE", flush=True)
sys.exit(0)
