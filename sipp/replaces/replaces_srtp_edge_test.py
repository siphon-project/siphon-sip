#!/usr/bin/env python3
"""Acceptance test for a `Replaces` takeover of a held call at an SRTP edge.

The shape of an attended transfer run by an SRTP peer in front of a plain-RTP
trunk: the SRTP side places a call, puts it on hold, and then a second SRTP
caller takes that dialog over with `Replaces` (RFC 3891 §3). The caller is
replaced, the plain-RTP callee survives.

The plain takeover test (replaces_takeover_test.py) proves the signalling. This
one proves the answer the new caller is given is one it can use, against a real
media engine:

  1. it is in the new caller's own transport, RTP/SAVP, and carries an
     `a=crypto` key (RFC 4568). SAVP without a key cannot be set up, and the
     new caller hangs up at once;
  2. it is not on hold. The new caller offered `sendrecv`; the hold belonged to
     the dialog that was replaced, and RFC 3264 §6.1 answers the offer in hand;
  3. the survivor is re-INVITEd in ITS transport, RTP/AVP with no key, and off
     hold.

Prints one `REPLACES-SRTP-VERDICT <json>` line; the CI step greps for
`"ok": true`.
"""
import json
import sys
import uuid

from replaces_takeover_test import (
    ALICE_PORT,
    BOB_PORT,
    CAROL_PORT,
    SELF_IP,
    SIPHON_HOST,
    Party,
    ack_for,
    body_of,
    establish,
    header,
    in_dialog,
    invite,
    method_of,
    status_of,
    tag_of,
)

CRYPTO = "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{key}\r\n"
ALICE_KEY = "WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz"
CAROL_KEY = "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
HOLD_DIRECTIONS = ("a=inactive", "a=sendonly", "a=recvonly")


def sdp(session_id, version, port, transport, direction, key=None):
    return (
        "v=0\r\n"
        f"o=- {session_id} {version} IN IP4 {SELF_IP}\r\n"
        "s=-\r\n"
        f"c=IN IP4 {SELF_IP}\r\n"
        "t=0 0\r\n"
        f"m=audio {port} {transport} 0 8\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        + (CRYPTO.format(key=key) if key else "")
        + f"a={direction}\r\n"
    )


def reinvite(party, dialog, cseq, body):
    """A re-INVITE on Alice's dialog (the A-leg), carrying `body`."""
    contact = dialog["alice_contact"] or f"<sip:{SIPHON_HOST}>"
    ruri = contact.strip("<>").split(">")[0].lstrip("<")
    lines = [
        f"INVITE {ruri} SIP/2.0",
        f"Via: SIP/2.0/UDP {SELF_IP}:{party.port};branch=z9hG4bK{uuid.uuid4().hex[:12]}",
        f"From: <sip:{party.name}@{SELF_IP}>;tag={dialog['alice_tag']}",
        f"To: <sip:bob@{SIPHON_HOST}>;tag={dialog['siphon_a_tag']}",
        f"Call-ID: {dialog['a_call_id']}",
        f"CSeq: {cseq} INVITE",
        f"Contact: {party.contact}",
        "Max-Forwards: 70",
        "Content-Type: application/sdp",
        f"Content-Length: {len(body)}",
    ]
    return "\r\n".join(lines) + "\r\n\r\n" + body


def media_line(body):
    for line in body.split("\r\n"):
        if line.startswith("m=audio"):
            return line
    return ""


def check_secure(body, what, problems):
    """`body` is what an SRTP party is sent: SAVP, keyed, and not on hold."""
    if " RTP/SAVP " not in media_line(body):
        problems.append(f"{what}: expected RTP/SAVP, got '{media_line(body)}'")
    if "a=crypto:" not in body:
        problems.append(f"{what}: RTP/SAVP with no a=crypto key")
    held = [direction for direction in HOLD_DIRECTIONS if direction in body]
    if held:
        problems.append(f"{what}: on hold ({held[0]})")


def check_plain(body, what, problems):
    """`body` is what a plain-RTP party is sent: AVP, no key, not on hold."""
    if " RTP/AVP " not in media_line(body):
        problems.append(f"{what}: expected RTP/AVP, got '{media_line(body)}'")
    if "a=crypto:" in body:
        problems.append(f"{what}: a=crypto sent to a plain-RTP party")
    held = [direction for direction in HOLD_DIRECTIONS if direction in body]
    if held:
        problems.append(f"{what}: on hold ({held[0]})")


def run(alice, bob, carol):
    problems = []
    observed = {}

    dialog = establish(
        alice,
        bob,
        "srtp-edge",
        caller_sdp=sdp(1000, 1, 40000, "RTP/SAVP", "sendrecv", ALICE_KEY),
    )
    # The baseline: an ordinary call across the edge is answered correctly, so
    # anything wrong below is the takeover's doing.
    check_secure(dialog["alice_answer"], "baseline answer to the caller", problems)
    check_plain(dialog["bob_offer"], "baseline offer to the callee", problems)

    # The caller puts the call on hold, the way a transferor does before it
    # hands the consult call over.
    alice.send(
        reinvite(alice, dialog, 2, sdp(1000, 2, 40000, "RTP/SAVP", "inactive", ALICE_KEY))
    )
    hold = bob.recv(
        lambda m: method_of(m) == "INVITE" and tag_of(header(m, "To")),
        "the hold re-INVITE reaching the callee",
    )
    bob.send(
        bob.respond(hold, 200, "OK", body=sdp(2000, 2, 40002, "RTP/AVP", "inactive"))
    )
    bob.recv(lambda m: method_of(m) == "ACK", "the ACK for the hold re-INVITE")
    hold_200 = alice.recv(
        lambda m: status_of(m) == 200 and (header(m, "CSeq") or "") == "2 INVITE",
        "the 200 OK for the hold re-INVITE",
    )
    alice.send(ack_for(alice, hold_200, dialog["a_call_id"], dialog["alice_tag"], 2))

    # The takeover: a second SRTP caller names the caller's dialog.
    replaces = (
        f"{dialog['a_call_id']};from-tag={dialog['alice_tag']}"
        f";to-tag={dialog['siphon_a_tag']}"
    )
    carol_call_id = f"srtp-edge-carol-{uuid.uuid4().hex[:8]}@{SELF_IP}"
    carol_tag = f"carol-{uuid.uuid4().hex[:8]}"
    carol.send(
        invite(
            carol,
            carol_call_id,
            carol_tag,
            "bob",
            sdp(3000, 1, 40004, "RTP/SAVP", "sendrecv", CAROL_KEY),
            extra=[f"Replaces: {replaces}", "Require: replaces"],
        )
    )
    carol_200 = carol.recv(
        lambda m: status_of(m) == 200 and (header(m, "CSeq") or "").endswith("INVITE"),
        "the 200 OK accepting the takeover",
    )
    observed["answer_to_new_caller"] = body_of(carol_200)
    check_secure(body_of(carol_200), "answer to the new caller", problems)
    carol.send(ack_for(carol, carol_200, carol_call_id, carol_tag, 1))

    replaced_bye = alice.recv(
        lambda m: method_of(m) == "BYE", "the BYE releasing the replaced caller"
    )
    alice.send(alice.respond(replaced_bye, 200, "OK"))

    survivor_reinvite = bob.recv(
        lambda m: method_of(m) == "INVITE" and tag_of(header(m, "To")),
        "the re-INVITE re-pointing the surviving callee",
    )
    observed["offer_to_survivor"] = body_of(survivor_reinvite)
    check_plain(body_of(survivor_reinvite), "re-INVITE to the survivor", problems)
    bob.send(
        bob.respond(
            survivor_reinvite,
            200,
            "OK",
            body=sdp(2000, 3, 40002, "RTP/AVP", "sendrecv"),
        )
    )
    bob.recv(lambda m: method_of(m) == "ACK", "the ACK for the survivor re-INVITE")

    # Tear down from the new caller; it reaching the callee proves the bridge.
    carol_contact = header(carol_200, "Contact") or f"<sip:{SIPHON_HOST}>"
    carol.send(
        in_dialog(
            carol,
            "BYE",
            carol_call_id,
            f"sip:carol@{SELF_IP}",
            carol_tag,
            f"sip:bob@{SIPHON_HOST}",
            tag_of(header(carol_200, "To")),
            2,
            carol_contact.strip("<>").split(">")[0].lstrip("<"),
        )
    )
    carol.recv(lambda m: status_of(m) == 200, "the 200 for the new caller's BYE")
    survivor_bye = bob.recv(
        lambda m: method_of(m) == "BYE", "the BYE reaching the surviving callee"
    )
    bob.send(bob.respond(survivor_bye, 200, "OK"))
    return problems, observed


def main():
    alice = Party("alice", ALICE_PORT)
    bob = Party("bob", BOB_PORT)
    carol = Party("carol", CAROL_PORT)

    observed = {}
    try:
        problems, observed = run(alice, bob, carol)
    except AssertionError as error:
        problems = [str(error)]
    except Exception as error:  # noqa: BLE001 - the verdict must survive anything
        problems = [f"{type(error).__name__}: {error}"]

    for name, body in observed.items():
        print(f"--- {name} ---\n{body}", flush=True)
    print(
        "REPLACES-SRTP-VERDICT " + json.dumps({"ok": not problems, "problems": problems}),
        flush=True,
    )
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
