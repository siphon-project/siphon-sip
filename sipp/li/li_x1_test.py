#!/usr/bin/env python3
"""Drive sipgate's LI simulator against siphon and check the whole path.

The simulator (https://github.com/sipgate/li-simulator-x1x2x3, MIT) plays both
the Administration Function and the Mediation and Delivery Function. It is an
independent implementation of TS 103 221, built from the same schema by other
people, which is what makes agreement meaningful — siphon validating against
its own reader would prove nothing.

This script drives the simulator's REST API and asserts on the answers. It
implements no part of X1 itself, deliberately: the peer is the reference.

What it checks, in order:

  1. **Provisioning** — create a destination and activate a task, over real
     mutual TLS. The simulator's client certificate CN is ``simulator`` and
     siphon binds ``admfIdentifier`` to it, so a successful activation is also
     proof the certificate binding passed rather than being skipped.
  2. **Read-back** — ``GetTaskDetails`` must report what was provisioned.
  3. **Refusals** — a duplicate XID, and removing a destination a task still
     delivers to. Refusing correctly is as much a part of conformance as
     accepting; a network element that accepted everything would pass a
     success-only test.
  4. **Delivery** — place a call the warrant matches and check IRI reached the
     mediation function.
  5. **Teardown** — deactivate, and confirm the warrant is gone.

Exit code is the test result.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import socket
import urllib.parse
import urllib.request

SIMULATOR = os.environ.get("SIMULATOR_URL", "http://127.0.0.1:8080")
SIPHON_SIP = os.environ.get("SIPHON_SIP", "network-element:5060")
SIPP_SCENARIO = os.environ.get("SIPP_SCENARIO", "/sipp/scenarios/li/li_target_uac.xml")
RUN_CALL = os.environ.get("RUN_CALL", "true").lower() == "true"

TASK_XID = os.environ.get("TASK_XID", "11111111-2222-3333-4444-555555555555")
DESTINATION_DID = os.environ.get("X2_DID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
# The simulator provisions on an E.164 target identifier, so the call must
# involve that number for the warrant to match. siphon's matcher normalises
# `sip:<number>@host` down to the bare digits, which is what makes this work.
TARGET_E164 = os.environ.get("TARGET_E164", "15551234567")
X2X3_PORT = os.environ.get("X2X3_PORT", "42069")
# Where the mediation function listens.
#
# Resolved to a literal here rather than passed as a name: TS 103 280's
# `IPAddressPort` carries an `IPv4Address`, which is a dotted quad by
# definition, so a hostname is not a legal value for this field and siphon
# rightly refuses one.
MDF_HOST = socket.gethostbyname(os.environ.get("MDF_HOST", "simulator"))
# Both interfaces, because the media engine is in this profile and content
# delivery is the half a signalling-only warrant would never exercise.
DELIVERY_TYPE = os.environ.get("DELIVERY_TYPE", "X_2_AND_X_3")
# Where the call goes. The domain has to be one siphon serves, or it forwards
# rather than handling it.
TARGET_DOMAIN = os.environ.get("TARGET_DOMAIN", "siphon.test")
CALLER_USER = os.environ.get("CALLER_USER", "caller")

# TS 103 221-2 clause 5.2: the fields the mediation function reads first.
PDU_TYPE_X2 = 1
PDU_TYPE_X3 = 2
PAYLOAD_FORMAT_SIP = 9
PAYLOAD_FORMAT_RTP = 8

failures: list[str] = []


def fail(message: str) -> None:
    print(f"  FAIL: {message}", flush=True)
    failures.append(message)


def note(message: str) -> None:
    print(f"  {message}", flush=True)


def request(method: str, path: str, form: dict | None = None) -> tuple[int, str]:
    """One REST call. POSTs are form-encoded, which is what the simulator takes."""
    url = f"{SIMULATOR}{path}"
    data = None
    headers = {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()
    except Exception as error:  # noqa: BLE001 - a connection problem is a result too
        return 0, str(error)


def wait_for(label: str, probe, timeout: int = 180) -> bool:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        ok, detail = probe()
        if ok:
            return True
        last = detail
        time.sleep(2)
    note(f"last {label} attempt: {last}")
    return False


# ---------------------------------------------------------------------------


def probe_simulator() -> tuple[bool, str]:
    status, body = request("GET", "/health")
    if status == 200:
        return True, ""
    # Spring Boot's management endpoints are served at the root here.
    status, body = request("GET", "/index")
    return status in (200, 400, 500), f"{status}: {body[:120]}"


def probe_network_element() -> tuple[bool, str]:
    """`/index` makes the simulator talk X1 to siphon, so it is the real probe."""
    status, body = request("GET", "/index")
    return status == 200, f"{status}: {body[:200]}"


def provision() -> bool:
    print("\n[1] provisioning over X1 (mutual TLS; admfIdentifier bound to the certificate CN)")

    status, body = request(
        "POST",
        "/destination",
        {
            "dId": DESTINATION_DID,
            "friendlyName": "sipp-li-test",
            "deliveryType": DELIVERY_TYPE,
            "tcpPort": X2X3_PORT,
            "ipAddress": MDF_HOST,
        },
    )
    if status != 200:
        fail(f"CreateDestination was refused: {status} {body[:400]}")
        return False
    note(f"destination {DESTINATION_DID[:8]}… created ({DELIVERY_TYPE})")

    status, body = request(
        "POST",
        "/task",
        {
            "e164number": TARGET_E164,
            "destinationId": DESTINATION_DID,
            "xId": TASK_XID,
            "deliveryType": DELIVERY_TYPE,
        },
    )
    if status != 200:
        fail(f"ActivateTask was refused: {status} {body[:400]}")
        return False
    note(f"task {TASK_XID[:8]}… activated on {TARGET_E164}")
    return True


def read_back() -> None:
    print("\n[2] reading the warrant back")
    status, body = request("GET", f"/task/{TASK_XID}")
    if status != 200:
        fail(f"GetTaskDetails failed: {status} {body[:400]}")
        return
    if TARGET_E164 not in body:
        fail(f"GetTaskDetails did not report the provisioned target: {body[:400]}")
        return
    note("GetTaskDetails reports the provisioned target")


def check_refusals() -> None:
    print("\n[3] refusals")

    status, body = request(
        "POST",
        "/task",
        {
            "e164number": TARGET_E164,
            "destinationId": DESTINATION_DID,
            "xId": TASK_XID,
            "deliveryType": DELIVERY_TYPE,
        },
    )
    if status == 200:
        fail("a duplicate XID was accepted; TS 103 221-1 requires 2010")
    elif "2010" in body:
        note("duplicate XID refused with 2010")
    else:
        note(f"duplicate XID refused ({status}) but without code 2010: {body[:200]}")

    status, body = request("DELETE", f"/destination/{DESTINATION_DID}")
    if status == 200:
        fail(
            "a destination still referenced by a task was removed; that would leave the "
            "warrant provisioned and delivering nowhere (expected 7010)"
        )
    elif "7010" in body:
        note("removing a referenced destination refused with 7010")
    else:
        note(f"removing a referenced destination refused ({status}): {body[:200]}")


def place_call() -> None:
    print("\n[4] placing a call the warrant matches")

    status, _ = request("POST", "/x2x3/reset")
    note(f"delivery buffer reset ({status})")

    command = [
        "sipp",
        SIPHON_SIP,
        "-sf",
        SIPP_SCENARIO,
        # The warrant is provisioned on an E.164 target identifier, so the call
        # has to carry that number for the match to happen at all. It goes in
        # the Request-URI and To, which is the terminating party.
        "-key",
        "to_uri",
        f"{TARGET_E164}@{TARGET_DOMAIN}",
        "-key",
        "from_user",
        CALLER_USER,
        "-key",
        "from_host",
        TARGET_DOMAIN,
        "-m",
        "1",
        "-r",
        "1",
        # A media port, because the scenario streams RTP: without content on
        # the wire an X3 assertion would pass on an empty interception.
        "-mp",
        "6000",
        "-timeout",
        "30s",
        "-nostdin",
    ]
    note(f"running: {' '.join(command)}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=90)
    except FileNotFoundError:
        note("sipp is not on PATH in this container; skipping the call leg")
        return
    except subprocess.TimeoutExpired:
        fail("the SIPp call timed out")
        return

    if result.returncode != 0:
        note(f"sipp exited {result.returncode}")
        note(result.stdout[-1200:])
        fail("the SIPp call did not complete")
        return
    note("call completed")


def decode_pdu(raw: bytes) -> dict | None:
    """Read a TS 103 221-2 PDU header the way clause 5.2 lays it out.

    Deliberately hand-rolled here rather than shared with anything siphon uses:
    this side of the test is the reader, and a reader that shared code with the
    writer would agree with it about a field we misplaced.
    """
    if len(raw) < 40:
        return None
    header_length = int.from_bytes(raw[4:8], "big")
    payload_length = int.from_bytes(raw[8:12], "big")
    if header_length < 40 or len(raw) < header_length + payload_length:
        return None
    xid = raw[16:32].hex()
    return {
        "major": raw[0],
        "minor": raw[1],
        "pdu_type": int.from_bytes(raw[2:4], "big"),
        "header_length": header_length,
        "payload_length": payload_length,
        "payload_format": int.from_bytes(raw[12:14], "big"),
        "direction": int.from_bytes(raw[14:16], "big"),
        "xid": f"{xid[0:8]}-{xid[8:12]}-{xid[12:16]}-{xid[16:20]}-{xid[20:32]}",
        "correlation": raw[32:40].hex(),
        "payload": raw[header_length : header_length + payload_length],
    }


def check_delivery() -> None:
    print("\n[5] delivery to the mediation function")
    # Let the delivery path flush.
    time.sleep(5)

    status, body = request("GET", "/x2x3/all")
    if status != 200:
        fail(f"could not read the received PDUs: {status} {body[:300]}")
        return
    try:
        received = json.loads(body)
    except json.JSONDecodeError:
        fail(f"the PDU list was not JSON: {body[:300]}")
        return

    note(f"the mediation function received {len(received)} PDU(s)")
    if not received:
        fail("no IRI reached the mediation function for a matched warrant")
        return

    decoded = []
    for entry in received:
        try:
            raw = base64.b64decode(entry)
        except Exception:  # noqa: BLE001 - the encoding is the simulator's business
            fail(f"a delivered PDU was not base64: {str(entry)[:120]}")
            continue
        pdu = decode_pdu(raw)
        if pdu is None:
            fail(f"a delivered PDU was not a readable TS 103 221-2 header: {raw[:16].hex()}")
            continue
        decoded.append(pdu)

    if not decoded:
        return

    # Every PDU, whichever interface, must carry the header the specification
    # fixes and the XID of the warrant that produced it. A record delivered
    # under the wrong XID is worse than a missing one: it attributes traffic to
    # somebody else's warrant.
    for pdu in decoded:
        if (pdu["major"], pdu["minor"]) != (0, 5):
            fail(f"a delivered PDU declared version {pdu['major']}.{pdu['minor']}, not 0.5")
            break
        if pdu["xid"] != TASK_XID:
            fail(f"a delivered PDU carried XID {pdu['xid']}, not the warrant's {TASK_XID}")
            break
        if pdu["correlation"] == "0" * 16:
            fail("a delivered PDU carried an all-zero correlation, which is reserved for keepalives")
            break

    x2 = [pdu for pdu in decoded if pdu["pdu_type"] == PDU_TYPE_X2]
    x3 = [pdu for pdu in decoded if pdu["pdu_type"] == PDU_TYPE_X3]
    note(f"    {len(x2)} X2 (signalling), {len(x3)} X3 (content)")

    # --- X2 ---------------------------------------------------------------
    if not x2:
        fail("no X2 signalling record reached the mediation function")
    else:
        formats = {pdu["payload_format"] for pdu in x2}
        if formats != {PAYLOAD_FORMAT_SIP}:
            fail(f"X2 records carried payload format(s) {sorted(formats)}, expected {PAYLOAD_FORMAT_SIP} (SIP)")
        else:
            note(f"    X2 payload format is SIP ({PAYLOAD_FORMAT_SIP})")

        # The payload is supposed to be the SIP message itself, so it has to
        # read as one — and it has to be *this* call's.
        methods = set()
        carried_target = False
        for pdu in x2:
            first_line = pdu["payload"].split(b"\r\n", 1)[0].decode("utf-8", "replace")
            methods.add(first_line.split(" ", 1)[0])
            if TARGET_E164.encode() in pdu["payload"]:
                carried_target = True
        note(f"    X2 payloads are real SIP: {', '.join(sorted(methods))}")
        if "INVITE" not in methods:
            fail(f"no INVITE among the delivered X2 records (saw {sorted(methods)})")
        if not carried_target:
            fail(f"no delivered X2 record carried the provisioned target {TARGET_E164}")
        else:
            note(f"    a delivered X2 record carries the target {TARGET_E164}")

        # Clause 5.2.6 is target-relative. The warrant names the called party
        # here, so the INVITE is travelling towards the target.
        directions = {pdu["direction"] for pdu in x2}
        if directions - {2, 3}:
            fail(f"X2 records carried direction(s) {sorted(directions)}; 2 or 3 expected")
        else:
            note(f"    X2 direction(s) {sorted(directions)} (2=to target, 3=from target)")

    # --- X3 ---------------------------------------------------------------
    if DELIVERY_TYPE != "X_2_AND_X_3":
        return
    if not x3:
        fail(
            "the warrant asked for content and the call carried RTP, but no X3 "
            "record reached the mediation function"
        )
        return
    formats = {pdu["payload_format"] for pdu in x3}
    if formats != {PAYLOAD_FORMAT_RTP}:
        fail(f"X3 records carried payload format(s) {sorted(formats)}, expected {PAYLOAD_FORMAT_RTP} (RTP)")
    else:
        note(f"    X3 payload format is RTP ({PAYLOAD_FORMAT_RTP})")

    # An X3 payload is a bare RTP packet: version 2 in the top two bits.
    bad = [pdu for pdu in x3 if not pdu["payload"] or (pdu["payload"][0] >> 6) != 2]
    if bad:
        fail(f"{len(bad)} X3 record(s) did not carry an RTP packet")
    else:
        note(f"    all {len(x3)} X3 payloads are RTP version 2")

    # X2 and X3 for one session must share a correlation, which is the whole
    # point of the field: it is how the mediation function ties the content to
    # the signalling that describes it.
    if x2:
        x2_correlations = {pdu["correlation"] for pdu in x2}
        x3_correlations = {pdu["correlation"] for pdu in x3}
        if not (x2_correlations & x3_correlations):
            fail(
                f"X2 and X3 carried different correlations ({sorted(x2_correlations)} vs "
                f"{sorted(x3_correlations)}); the mediation function cannot tie them together"
            )
        else:
            note("    X2 and X3 share a correlation ID")


def teardown() -> None:
    print("\n[6] teardown")
    status, body = request("DELETE", f"/task/{TASK_XID}")
    if status != 200:
        fail(f"DeactivateTask failed: {status} {body[:300]}")
    else:
        note("task deactivated")

    status, _ = request("DELETE", f"/destination/{DESTINATION_DID}")
    note(f"destination removed ({status})")

    # A deactivated task must be gone, not merely marked inactive.
    status, body = request("GET", f"/task/{TASK_XID}")
    if status == 200:
        fail("the task is still reported after deactivation")
    else:
        note(f"the deactivated task is gone ({status})")


def main() -> int:
    print(
        "ETSI TS 103 221-1 interop\n"
        "  network element: siphon\n"
        "  ADMF + MDF:      sipgate li-simulator-x1x2x3"
    )

    if not wait_for("simulator", probe_simulator):
        print("\nFAIL: the simulator never became reachable")
        return 1
    note("simulator is up")

    if not wait_for("network element", probe_network_element):
        print("\nFAIL: the simulator could not reach siphon's X1 listener")
        return 1
    note("the simulator reached siphon's X1 listener")

    if provision():
        read_back()
        check_refusals()
        if RUN_CALL:
            place_call()
            check_delivery()
        teardown()

    print()
    if failures:
        print(f"RESULT: {len(failures)} failure(s)")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("RESULT: all ETSI X1 interop checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
