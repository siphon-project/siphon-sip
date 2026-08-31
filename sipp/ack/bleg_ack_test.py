#!/usr/bin/env python3
"""Acceptance test: the callee is ACKed on every answered B2BUA call.

siphon uses the late-ACK pattern (RFC 3261 §14.1) — it does not ACK the callee's
200 immediately, it holds the ACK until the caller ACKs and then sends it. If
that deferred ACK is never armed, the callee's INVITE transaction never
completes: it retransmits its 200 to Timer B and tears the call down, seconds
after everyone thinks the call is up. Nothing on the caller's side looks wrong,
which is exactly why this needs its own gate.

The existing SIPp suites did not catch it. It only appears when a call's 18x and
its 200 are processed concurrently, which needs back-to-back calls with no pause
between the ringing and the answer — a shape the scenario files do not produce.
This peer drives plain calls in a tight loop and fails if ANY of them leaves the
callee unacknowledged.

Prints one `ACK-REPRO <json>` line; the CI step greps for `"failures": 0`.
"""

import json, os, socket, sys, time, uuid

SIPHON = os.environ.get("SIPHON_ADDR", "172.20.0.114:5060")
SELF_IP = os.environ.get("SELF_IP", "172.20.0.115")
CALLS = int(os.environ.get("CALLS", "40"))
HOST, PORT = SIPHON.split(":")
ADDR = (HOST, int(PORT))


def sdp(port):
    return ("v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"
            "m=audio %d RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n" % (SELF_IP, SELF_IP, port))


def header(m, name):
    for line in m.split("\r\n"):
        if ":" in line and line[:1] not in (" ", "\t"):
            k, _, v = line.partition(":")
            if k.strip().lower() == name.lower():
                return v.strip()
    return None


def start(m):
    return m.split("\r\n", 1)[0]


def method(m):
    l = start(m)
    return None if l.startswith("SIP/2.0") else l.split(None, 1)[0]


def status(m):
    l = start(m)
    return int(l.split()[1]) if l.startswith("SIP/2.0") else None


class P:
    def __init__(self, name, port):
        self.name, self.port = name, port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((SELF_IP, port))
        self.s.settimeout(0.2)
        self.contact = "<sip:%s@%s:%d>" % (name, SELF_IP, port)

    def send(self, m):
        self.s.sendto(m.encode(), ADDR)

    def recv(self, pred, timeout=5):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                d, _ = self.s.recvfrom(65535)
            except socket.timeout:
                continue
            m = d.decode(errors="replace")
            if pred(m):
                return m
        return None

    def drain(self):
        while True:
            try:
                self.s.recvfrom(65535)
            except socket.timeout:
                return

    def respond(self, req, code, reason, body=None, tag=None):
        to = header(req, "To")
        if tag and ";tag=" not in (to or ""):
            to = "%s;tag=%s" % (to, tag)
        head = ["SIP/2.0 %d %s" % (code, reason), "Via: %s" % header(req, "Via"),
                "From: %s" % header(req, "From"), "To: %s" % to,
                "Call-ID: %s" % header(req, "Call-ID"), "CSeq: %s" % header(req, "CSeq"),
                "Contact: %s" % self.contact]
        if body:
            head += ["Content-Type: application/sdp", "Content-Length: %d" % len(body)]
            return "\r\n".join(head) + "\r\n\r\n" + body
        head.append("Content-Length: 0")
        return "\r\n".join(head) + "\r\n\r\n"


def one_call(alice, bob, n):
    alice.drain(); bob.drain()
    cid = "ack-%d-%s@%s" % (n, uuid.uuid4().hex[:6], SELF_IP)
    ftag = "a%s" % uuid.uuid4().hex[:8]
    alice.send("\r\n".join([
        "INVITE sip:bob@%s SIP/2.0" % HOST,
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s" % (SELF_IP, alice.port, uuid.uuid4().hex[:12]),
        "From: <sip:alice@%s>;tag=%s" % (SELF_IP, ftag),
        "To: <sip:bob@%s>" % HOST, "Call-ID: %s" % cid, "CSeq: 1 INVITE",
        "Contact: %s" % alice.contact, "Max-Forwards: 70",
        "Content-Type: application/sdp", "Content-Length: %d" % len(sdp(40000)),
    ]) + "\r\n\r\n" + sdp(40000))

    binv = bob.recv(lambda m: method(m) == "INVITE" and ";tag=" not in (header(m, "To") or ""))
    if not binv:
        return ("no-b-invite", cid, None)
    bcid = header(binv, "Call-ID")
    btag = "b%s" % uuid.uuid4().hex[:8]
    bob.send(bob.respond(binv, 180, "Ringing", tag=btag))
    bob.send(bob.respond(binv, 200, "OK", body=sdp(40002), tag=btag))

    a200 = alice.recv(lambda m: status(m) == 200 and (header(m, "CSeq") or "").endswith("INVITE"))
    if not a200:
        return ("no-a-200", cid, bcid)
    ct = header(a200, "Contact") or "<sip:%s>" % HOST
    ruri = ct.strip("<>").split(">")[0].lstrip("<")
    alice.send("\r\n".join([
        "ACK %s SIP/2.0" % ruri,
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s" % (SELF_IP, alice.port, uuid.uuid4().hex[:12]),
        "From: %s" % header(a200, "From"), "To: %s" % header(a200, "To"),
        "Call-ID: %s" % cid, "CSeq: 1 ACK", "Max-Forwards: 70", "Content-Length: 0",
    ]) + "\r\n\r\n")

    back = bob.recv(lambda m: method(m) == "ACK", timeout=4)
    verdict = "ok" if back else "NO-B-LEG-ACK"

    # Tear down from alice so the next call starts clean.
    alice.send("\r\n".join([
        "BYE %s SIP/2.0" % ruri,
        "Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK%s" % (SELF_IP, alice.port, uuid.uuid4().hex[:12]),
        "From: %s" % header(a200, "From"), "To: %s" % header(a200, "To"),
        "Call-ID: %s" % cid, "CSeq: 2 BYE", "Max-Forwards: 70", "Content-Length: 0",
    ]) + "\r\n\r\n")
    alice.recv(lambda m: status(m) == 200, timeout=3)
    bbye = bob.recv(lambda m: method(m) == "BYE", timeout=3)
    if bbye:
        bob.send(bob.respond(bbye, 200, "OK", tag=btag))
    return (verdict, cid, bcid)


def main():
    alice, bob = P("alice", 6001), P("bob", 6002)
    bad = []
    for n in range(CALLS):
        v, cid, bcid = one_call(alice, bob, n)
        if v != "ok":
            bad.append({"call": n, "verdict": v, "a_call_id": cid, "b_call_id": bcid})
        time.sleep(0.05)
    print("ACK-REPRO " + json.dumps({"calls": CALLS, "failures": len(bad), "detail": bad[:8]}), flush=True)
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
