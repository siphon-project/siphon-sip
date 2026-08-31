#!/usr/bin/env python3
"""Acceptance test for inbound `INVITE` with `Replaces` (RFC 3891 / RFC 5589 §7).

A transferee that is handed an attended transfer calls the transfer target
naming the dialog it is taking over. When that target is behind siphon, the
INVITE arrives here carrying `Replaces`, and siphon has to hand the *existing*
call over: the named party is dropped, the new caller takes its place, and the
party on the other side carries on without ever seeing a new call.

Driving this from SIPp is not practical — the takeover INVITE has to quote dialog
identifiers (a Call-ID and both tags) that only exist once the first call is up,
and one of them is siphon's own tag, which is minted at runtime. So this peer
plays all three parties over three UDP sockets and quotes what it observed.

Both directions are covered, because which leg the header names depends on who
started the call being transferred:

  case "a-leg"  the transferor is the CALLER, so the named dialog is siphon's
                A-leg and the callee survives.
  case "b-leg"  the transferor is the CALLEE (the everyday "answer, then
                transfer" case, and the shape of a directed pickup), so the
                named dialog is siphon's B-leg and the caller survives.

Each case asserts the three things that make a takeover real rather than a
connected call with dead audio:

  1. the taking-over INVITE is answered 2xx **with a body** — an answer with no
     SDP means nothing was re-anchored;
  2. the replaced party is sent a BYE (RFC 3891 §3 requires the replaced dialog
     to be terminated), and
  3. the SURVIVING party is re-INVITEd (RFC 3261 §14) — without it the survivor
     keeps sending media to the party that just left, which is the failure that
     looks fine in SIP and is silent on the wire.

Prints one `REPLACES-VERDICT <json>` line; the CI step greps for `"ok": true`.
"""
import json
import os
import re
import socket
import sys
import time
import uuid

SIPHON = os.environ.get("SIPHON_ADDR", "172.20.0.60:5060")
SELF_IP = os.environ.get("SELF_IP", "172.20.0.70")
TIMEOUT = float(os.environ.get("STEP_TIMEOUT", "10"))

SIPHON_HOST, SIPHON_PORT = SIPHON.split(":")
SIPHON_ADDR = (SIPHON_HOST, int(SIPHON_PORT))

ALICE_PORT, BOB_PORT, CAROL_PORT = 6001, 6002, 6003


def sdp(session_id, port):
    return (
        "v=0\r\n"
        f"o=- {session_id} {session_id} IN IP4 {SELF_IP}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {SELF_IP}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} RTP/AVP 0 8\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        "a=sendrecv\r\n"
    )


def header(message, name):
    """First value of `name`, case-insensitively, or None."""
    for line in message.split("\r\n"):
        if not line or line[0] in " \t":
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() == name.lower():
            return value.strip()
    return None


def tag_of(value):
    match = re.search(r"[;,]\s*tag=([^;>\s]+)", value or "")
    return match.group(1) if match else None


def body_of(message):
    _, _, body = message.partition("\r\n\r\n")
    return body


def start_line(message):
    return message.split("\r\n", 1)[0]


def status_of(message):
    line = start_line(message)
    if line.startswith("SIP/2.0"):
        return int(line.split()[1])
    return None


def method_of(message):
    line = start_line(message)
    if line.startswith("SIP/2.0"):
        return None
    return line.split(None, 1)[0]


class Party:
    """One UDP endpoint that can act as UAC and UAS."""

    def __init__(self, name, port):
        self.name = name
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((SELF_IP, port))
        self.socket.settimeout(0.25)
        self.contact = f"<sip:{name}@{SELF_IP}:{port}>"

    def send(self, message):
        self.socket.sendto(message.encode(), SIPHON_ADDR)

    def recv(self, predicate, what, timeout=TIMEOUT):
        """Wait for a message satisfying `predicate`, ignoring anything else.

        Retransmissions and messages belonging to another step of the flow are
        skipped rather than failing the run — the point of a step is that the
        expected message eventually arrives, not that nothing else does.
        """
        deadline = time.monotonic() + timeout
        seen = []
        while time.monotonic() < deadline:
            try:
                data, _ = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            message = data.decode(errors="replace")
            if predicate(message):
                return message
            seen.append(start_line(message))
        raise AssertionError(
            f"{self.name}: timed out waiting for {what}; saw {seen or 'nothing'}"
        )

    def drain(self):
        """Discard anything still queued, so one case cannot bleed into the next."""
        while True:
            try:
                self.socket.recvfrom(65535)
            except socket.timeout:
                return

    def expect_nothing(self, predicate, what, window=1.5):
        """Fail if a matching message arrives inside `window`."""
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            try:
                data, _ = self.socket.recvfrom(65535)
            except socket.timeout:
                continue
            message = data.decode(errors="replace")
            if predicate(message):
                raise AssertionError(f"{self.name}: unexpected {what}: {start_line(message)}")

    def respond(self, request, code, reason, body=None, local_tag=None):
        to_value = header(request, "To")
        if local_tag and not tag_of(to_value):
            to_value = f"{to_value};tag={local_tag}"
        lines = [
            f"SIP/2.0 {code} {reason}",
            f"Via: {header(request, 'Via')}",
            f"From: {header(request, 'From')}",
            f"To: {to_value}",
            f"Call-ID: {header(request, 'Call-ID')}",
            f"CSeq: {header(request, 'CSeq')}",
            f"Contact: {self.contact}",
        ]
        if body:
            lines.append("Content-Type: application/sdp")
            lines.append(f"Content-Length: {len(body)}")
            return "\r\n".join(lines) + "\r\n\r\n" + body
        lines.append("Content-Length: 0")
        return "\r\n".join(lines) + "\r\n\r\n"


def invite(party, call_id, from_tag, target, body, extra=None, cseq=1):
    lines = [
        f"INVITE sip:{target}@{SIPHON_HOST} SIP/2.0",
        f"Via: SIP/2.0/UDP {SELF_IP}:{party.port};branch=z9hG4bK{uuid.uuid4().hex[:12]}",
        f"From: <sip:{party.name}@{SELF_IP}>;tag={from_tag}",
        f"To: <sip:{target}@{SIPHON_HOST}>",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} INVITE",
        f"Contact: {party.contact}",
        "Max-Forwards: 70",
        "User-Agent: siphon-replaces-acceptance",
    ]
    if extra:
        lines.extend(extra)
    lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body)}")
    return "\r\n".join(lines) + "\r\n\r\n" + body


def in_dialog(party, method, call_id, from_uri, from_tag, to_uri, to_tag, cseq, contact_uri):
    lines = [
        f"{method} {contact_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {SELF_IP}:{party.port};branch=z9hG4bK{uuid.uuid4().hex[:12]}",
        f"From: <{from_uri}>;tag={from_tag}",
        f"To: <{to_uri}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} {method}",
        f"Contact: {party.contact}",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    return "\r\n".join(lines) + "\r\n\r\n"


def ack_for(party, response, call_id, from_tag, cseq):
    contact = header(response, "Contact") or f"<sip:{SIPHON_HOST}>"
    ruri = contact.strip("<>").split(">")[0].lstrip("<")
    lines = [
        f"ACK {ruri} SIP/2.0",
        f"Via: SIP/2.0/UDP {SELF_IP}:{party.port};branch=z9hG4bK{uuid.uuid4().hex[:12]}",
        f"From: {header(response, 'From')}",
        f"To: {header(response, 'To')}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq} ACK",
        "Max-Forwards: 70",
        "Content-Length: 0",
    ]
    return "\r\n".join(lines) + "\r\n\r\n"


def establish(alice, bob, label):
    """Alice calls through siphon; Bob answers. Returns both dialogs' identifiers."""
    call_id = f"{label}-alice-{uuid.uuid4().hex[:8]}@{SELF_IP}"
    alice_tag = f"alice-{uuid.uuid4().hex[:8]}"
    alice.send(invite(alice, call_id, alice_tag, "bob", sdp(1000, 40000)))

    # An INITIAL INVITE only. A re-INVITE (or a retransmission of one) left over
    # from an earlier case carries a To-tag, and picking that up here would quote
    # a dead dialog in the Replaces and draw a 481.
    b_invite = bob.recv(
        lambda m: method_of(m) == "INVITE" and not tag_of(header(m, "To")),
        "the B-leg INVITE",
    )
    b_call_id = header(b_invite, "Call-ID")
    siphon_b_tag = tag_of(header(b_invite, "From"))
    bob_tag = f"bob-{uuid.uuid4().hex[:8]}"
    bob.send(bob.respond(b_invite, 180, "Ringing", local_tag=bob_tag))
    bob.send(bob.respond(b_invite, 200, "OK", body=sdp(2000, 40002), local_tag=bob_tag))

    # The caller is answered first and the callee's ACK only follows the
    # caller's, so both legs complete their INVITE transaction together
    # (RFC 3261 §14.1). Waiting on the B-leg ACK before ACKing here deadlocks.
    a_200 = alice.recv(
        lambda m: status_of(m) == 200 and (header(m, "CSeq") or "").endswith("INVITE"),
        "the 200 OK for Alice's INVITE",
    )
    siphon_a_tag = tag_of(header(a_200, "To"))
    alice.send(ack_for(alice, a_200, call_id, alice_tag, 1))

    # Best-effort, deliberately not an assertion. The callee's ACK is not what
    # this test measures, and siphon has a separate, pre-existing race that
    # occasionally drops it on an ordinary call setup (the deferred B-leg ACK is
    # armed while the A-leg 200 is already on its way out). Failing here would
    # make this job flap for a reason that has nothing to do with `Replaces`;
    # the B2BUA suite is what gates ACK behaviour.
    try:
        bob.recv(lambda m: method_of(m) == "ACK", "the B-leg ACK", timeout=3)
    except AssertionError:
        print(f"note[{label}]: no B-leg ACK observed (unrelated known race)", flush=True)

    assert siphon_a_tag, "siphon must tag the 200 it answers the caller with"
    assert siphon_b_tag, "siphon must tag the INVITE it sends the callee"
    return {
        "a_call_id": call_id,
        "alice_tag": alice_tag,
        "siphon_a_tag": siphon_a_tag,
        "b_call_id": b_call_id,
        "bob_tag": bob_tag,
        "siphon_b_tag": siphon_b_tag,
        "alice_contact": header(a_200, "Contact"),
    }


def run_case(case, alice, bob, carol):
    """Take a live call over and check the right party was replaced."""
    for party in (alice, bob, carol):
        party.drain()
    dialog = establish(alice, bob, case)

    if case == "a-leg":
        # The transferor is the caller: name siphon's A-leg. from-tag is the
        # remote (Alice's) tag and to-tag siphon's own, per RFC 3891 §3.
        replaces = (
            f"{dialog['a_call_id']};from-tag={dialog['alice_tag']}"
            f";to-tag={dialog['siphon_a_tag']}"
        )
        replaced, survivor = alice, bob
    else:
        # The transferor is the callee: name siphon's B-leg.
        replaces = (
            f"{dialog['b_call_id']};from-tag={dialog['bob_tag']}"
            f";to-tag={dialog['siphon_b_tag']}"
        )
        replaced, survivor = bob, alice

    carol_call_id = f"{case}-carol-{uuid.uuid4().hex[:8]}@{SELF_IP}"
    carol_tag = f"carol-{uuid.uuid4().hex[:8]}"
    carol.send(
        invite(
            carol,
            carol_call_id,
            carol_tag,
            "bob",
            sdp(3000, 40004),
            extra=[f"Replaces: {replaces}", "Require: replaces"],
        )
    )

    # 1. The takeover is accepted, and with media.
    carol_200 = carol.recv(
        lambda m: status_of(m) == 200 and (header(m, "CSeq") or "").endswith("INVITE"),
        "the 200 OK accepting the takeover",
    )
    assert body_of(carol_200).strip(), "the takeover was answered without an SDP body"
    carol.send(ack_for(carol, carol_200, carol_call_id, carol_tag, 1))

    # 2. The replaced party is released (RFC 3891 §3).
    replaced_bye = replaced.recv(
        lambda m: method_of(m) == "BYE", "the BYE releasing the replaced party"
    )
    replaced.send(replaced.respond(replaced_bye, 200, "OK"))

    # 3. The survivor is re-pointed at the new party (RFC 3261 §14). Without
    #    this it is still sending media to the party that just left.
    reinvite = survivor.recv(
        lambda m: method_of(m) == "INVITE" and tag_of(header(m, "To")),
        "the re-INVITE re-pointing the surviving party",
    )
    survivor_tag = tag_of(header(reinvite, "To"))
    survivor.send(survivor.respond(reinvite, 200, "OK", body=sdp(4000, 40006)))
    survivor.recv(lambda m: method_of(m) == "ACK", "the ACK for the survivor re-INVITE")

    # 4. The replaced party is gone for good — it must not also be re-INVITEd.
    replaced.expect_nothing(
        lambda m: method_of(m) == "INVITE", "re-INVITE to the replaced party"
    )

    # Tear the surviving call down from the new party and check it reaches the
    # far side, which only works if the two really are bridged.
    to_uri = f"sip:bob@{SIPHON_HOST}"
    carol_contact = header(carol_200, "Contact") or f"<sip:{SIPHON_HOST}>"
    carol.send(
        in_dialog(
            carol,
            "BYE",
            carol_call_id,
            f"sip:carol@{SELF_IP}",
            carol_tag,
            to_uri,
            tag_of(header(carol_200, "To")),
            2,
            carol_contact.strip("<>").split(">")[0].lstrip("<"),
        )
    )
    carol.recv(lambda m: status_of(m) == 200, "the 200 for the new party's BYE")
    survivor_bye = survivor.recv(
        lambda m: method_of(m) == "BYE", "the BYE reaching the surviving party"
    )
    survivor.send(survivor.respond(survivor_bye, 200, "OK", local_tag=survivor_tag))
    return True


def main():
    alice = Party("alice", ALICE_PORT)
    bob = Party("bob", BOB_PORT)
    carol = Party("carol", CAROL_PORT)

    results = {}
    ok = True
    for case in ("a-leg", "b-leg"):
        try:
            run_case(case, alice, bob, carol)
            results[case] = "ok"
        except AssertionError as error:
            results[case] = str(error)
            ok = False
        except Exception as error:  # noqa: BLE001 - the verdict must survive anything
            results[case] = f"{type(error).__name__}: {error}"
            ok = False

    print("REPLACES-VERDICT " + json.dumps({"ok": ok, "cases": results}), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
