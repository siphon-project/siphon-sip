#!/usr/bin/env python3
"""Does siphon actually detect a warrant on *every* target identifier type?

The X1 conformance question is answered elsewhere, by
[`li_x1_test.py`](li_x1_test.py) driving sipgate's simulator. This asks a
different and equally important one: for each identifier type an IMS warrant can
name, does a real call carrying that identity actually get intercepted?

A warrant that is accepted and then matches nothing is the failure this whole
module exists to prevent. It cannot be caught by a provisioning test, because
provisioning succeeds — the absence only shows up as product that never arrives.
So each type is provisioned, a call carrying it is placed through siphon with
SIPp, and the Mediation and Delivery Function is asked whether IRI turned up.

Provisioning here speaks X1 directly rather than going through the simulator,
because the simulator's REST API only exposes `e164number` and this needs the
whole set. Conformance of the messages is not what is under test — the simulator
covers that — so a direct client is the right tool.
"""

from __future__ import annotations

import json
import os
import ssl
import subprocess
import sys
import time
import urllib.error
import socket
import urllib.parse
import urllib.request
import uuid
from xml.etree import ElementTree

X1 = "http://uri.etsi.org/03221/X1/2017/10"
COMMON = "http://uri.etsi.org/03280/common/2017/07"
XSI = "http://www.w3.org/2001/XMLSchema-instance"

NE_URL = os.environ.get("NE_URL", "https://network-element:8443/X1/NE")
ADMF_ID = os.environ.get("ADMF_IDENTIFIER", "simulator")
NE_ID = os.environ.get("NE_IDENTIFIER", "network-element")
VERSION = os.environ.get("X1_VERSION", "v1.23.1")

CLIENT_CERT = os.environ.get("CLIENT_CERT", "/mutual-tls-stores/certs/simulator.crt")
CLIENT_KEY = os.environ.get("CLIENT_KEY", "/mutual-tls-stores/keys/simulator.key")
CA_CERT = os.environ.get("CA_CERT", "/mutual-tls-stores/ca-certs/network-element-ca.crt")

SIMULATOR = os.environ.get("SIMULATOR_URL", "http://simulator:8080")
SIPHON_SIP = os.environ.get("SIPHON_SIP", "network-element:5060")
UAC_SCENARIO = os.environ.get("UAC_SCENARIO", "/app/li_target_uac.xml")
CALLEE = os.environ.get("CALLEE", "callee@siphon.test")

DESTINATION_DID = "dddddddd-0000-4000-8000-000000000001"
# A literal, not a name: the dictionary's `IPv4Address` is a dotted quad.
DELIVERY_HOST = socket.gethostbyname(os.environ.get("MDF_HOST", "simulator"))
DELIVERY_PORT = int(os.environ.get("MDF_PORT", "42069"))

failures: list[str] = []


def fail(message: str) -> None:
    print(f"  FAIL: {message}", flush=True)
    failures.append(message)


def note(message: str) -> None:
    print(f"  {message}", flush=True)


# ---------------------------------------------------------------------------
# A direct X1 client
# ---------------------------------------------------------------------------


def timestamp() -> str:
    """A TS 103 280 QualifiedMicrosecondDateTime: exactly six fractional digits."""
    now = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1_000_000):06d}Z"


def envelope() -> tuple[str, str]:
    transaction_id = str(uuid.uuid4())
    return (
        f"<admfIdentifier>{ADMF_ID}</admfIdentifier>"
        f"<neIdentifier>{NE_ID}</neIdentifier>"
        f"<messageTimestamp>{timestamp()}</messageTimestamp>"
        f"<version>{VERSION}</version>"
        f"<x1TransactionId>{transaction_id}</x1TransactionId>",
        transaction_id,
    )


def post_x1(type_name: str, payload: str) -> str:
    body, _ = envelope()
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<X1Request xmlns="{X1}" xmlns:c="{COMMON}" xmlns:xsi="{XSI}">'
        f'<x1RequestMessage xsi:type="{type_name}">{body}{payload}</x1RequestMessage>'
        "</X1Request>"
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(CA_CERT)
    context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    request = urllib.request.Request(
        NE_URL, data=xml.encode(), headers={"Content-Type": "application/xml"}
    )
    with urllib.request.urlopen(request, context=context, timeout=20) as response:
        return response.read().decode()


def response_kind(xml: str) -> str:
    root = ElementTree.fromstring(xml)
    message = root.find(f"{{{X1}}}x1ResponseMessage")
    return message.get(f"{{{XSI}}}type", "?") if message is not None else "?"


def error_code(xml: str) -> str | None:
    root = ElementTree.fromstring(xml)
    found = root.find(f".//{{{X1}}}errorCode")
    return found.text if found is not None else None


# ---------------------------------------------------------------------------
# The target types
# ---------------------------------------------------------------------------

# Each entry is: label, the <targetIdentifier> child, and the call to place.
#
# `from_user`/`from_host` build the caller; `to_uri` is the called party. Which
# one carries the target decides whether the warrant matches the originating or
# the terminating side, and both directions are covered here on purpose.
TARGET_TYPES = [
    (
        "sipUri",
        "<sipUri>sip:alice@siphon.test</sipUri>",
        {"from_user": "alice", "from_host": "siphon.test", "to_uri": CALLEE},
    ),
    (
        "sipUri (terminating)",
        "<sipUri>sip:carol@siphon.test</sipUri>",
        {"from_user": "dave", "from_host": "siphon.test", "to_uri": "carol@siphon.test"},
    ),
    (
        "telUri",
        "<telUri>tel:15551110001</telUri>",
        {"from_user": "15551110001", "from_host": "siphon.test", "to_uri": CALLEE},
    ),
    (
        "e164Number",
        "<e164Number>15551110002</e164Number>",
        {"from_user": "15551110002", "from_host": "siphon.test", "to_uri": CALLEE},
    ),
    (
        "e164Number (dialled)",
        "<e164Number>15551110003</e164Number>",
        {"from_user": "eve", "from_host": "siphon.test", "to_uri": "15551110003@siphon.test"},
    ),
    (
        "impu",
        "<impu>sip:frank@ims.siphon.test</impu>",
        {"from_user": "frank", "from_host": "ims.siphon.test", "to_uri": CALLEE},
    ),
    (
        "impi",
        "<impi>grace@ims.siphon.test</impi>",
        {"from_user": "grace", "from_host": "ims.siphon.test", "to_uri": CALLEE},
    ),
]


def create_destination() -> bool:
    # Clear a destination left behind by an earlier run first. The DID is fixed
    # so a failure names the same thing every time, which means a second run
    # against a still-running element would otherwise be refused 2030 — a
    # correct answer to the wrong question, and one that reads as a regression.
    # An ADMF re-provisioning its own destination does exactly this.
    post_x1("RemoveDestinationRequest", f"<dId>{DESTINATION_DID}</dId>")

    payload = (
        "<destinationDetails>"
        f"<dId>{DESTINATION_DID}</dId>"
        "<friendlyName>target-type coverage</friendlyName>"
        "<deliveryType>X2Only</deliveryType>"
        "<deliveryAddress><ipAddressAndPort>"
        f"<c:address><c:IPv4Address>{DELIVERY_HOST}</c:IPv4Address></c:address>"
        f"<c:port><c:TCPPort>{DELIVERY_PORT}</c:TCPPort></c:port>"
        "</ipAddressAndPort></deliveryAddress>"
        "</destinationDetails>"
    )
    body = post_x1("CreateDestinationRequest", payload)
    if response_kind(body) != "CreateDestinationResponse":
        fail(f"CreateDestination failed: {response_kind(body)} / {error_code(body)}")
        return False
    note(f"destination {DESTINATION_DID[:8]}… created")
    return True


def activate(x_id: str, identifier_xml: str) -> bool:
    payload = (
        "<taskDetails>"
        f"<xId>{x_id}</xId>"
        f"<targetIdentifiers><targetIdentifier>{identifier_xml}</targetIdentifier></targetIdentifiers>"
        "<deliveryType>X2Only</deliveryType>"
        f"<listOfDIDs><dId>{DESTINATION_DID}</dId></listOfDIDs>"
        "</taskDetails>"
    )
    body = post_x1("ActivateTaskRequest", payload)
    if response_kind(body) != "ActivateTaskResponse":
        fail(f"ActivateTask failed: {response_kind(body)} / {error_code(body)}")
        return False
    return True


def deactivate(x_id: str) -> None:
    post_x1("DeactivateTaskRequest", f"<xId>{x_id}</xId>")


def simulator_get(path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(f"{SIMULATOR}{path}", timeout=20) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()
    except Exception as error:  # noqa: BLE001
        return 0, str(error)


def simulator_post(path: str) -> int:
    try:
        request = urllib.request.Request(f"{SIMULATOR}{path}", data=b"", method="POST")
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except Exception:  # noqa: BLE001
        return 0


def received_pdu_count() -> int:
    status, body = simulator_get("/x2x3/all")
    if status != 200:
        return -1
    try:
        return len(json.loads(body))
    except json.JSONDecodeError:
        return -1


def place_call(keys: dict[str, str]) -> bool:
    command = ["sipp", SIPHON_SIP, "-sf", UAC_SCENARIO, "-m", "1", "-r", "1",
               "-timeout", "25s", "-nostdin"]
    for key, value in keys.items():
        command += ["-key", key, value]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        fail(f"could not run sipp: {error}")
        return False
    if result.returncode != 0:
        note(f"    sipp exited {result.returncode}: {result.stdout[-500:]}")
        return False
    return True


def main() -> int:
    print("Does siphon detect a warrant on every target identifier type?")
    print(f"  network element: {NE_URL}")

    if not create_destination():
        return 1

    for label, identifier_xml, keys in TARGET_TYPES:
        print(f"\n[{label}]")
        x_id = str(uuid.uuid4())

        if not activate(x_id, identifier_xml):
            continue
        note(f"warrant {x_id[:8]}… active on {identifier_xml}")

        simulator_post("/x2x3/reset")
        before = received_pdu_count()

        placed = place_call(keys)
        if not placed:
            fail(f"{label}: the call did not complete, so detection is untested")
            deactivate(x_id)
            continue

        # Let the delivery path flush.
        time.sleep(2)
        after = received_pdu_count()

        if after < 0:
            fail(f"{label}: could not read the mediation function's buffer")
        elif after <= before:
            fail(
                f"{label}: the call completed but NO IRI reached the mediation function — "
                "the warrant was accepted and matched nothing"
            )
        else:
            note(f"detected: {after - max(before, 0)} record(s) delivered")

        deactivate(x_id)

    # --- negative control --------------------------------------------------
    #
    # Everything above asserts that a delivery *happened*, and a matcher that
    # matched everything would pass all of it. So one warrant is provisioned on
    # an identity no call carries, and the same call is placed: nothing may be
    # delivered. This is what makes the seven results above mean detection
    # rather than noise, and it is the only case here that fails if the whole
    # test has stopped discriminating.
    print("\n[negative control: a warrant nothing matches]")
    x_id = str(uuid.uuid4())
    if activate(x_id, "<e164Number>15559990000</e164Number>"):
        note(f"warrant {x_id[:8]}… active on a number no call carries")
        simulator_post("/x2x3/reset")
        if place_call(
            {"from_user": "mallory", "from_host": "siphon.test", "to_uri": CALLEE}
        ):
            time.sleep(2)
            delivered = received_pdu_count()
            if delivered > 0:
                fail(
                    "negative control: a warrant on an identity the call never "
                    f"carried delivered {delivered} record(s) — the matcher is "
                    "matching traffic it should not, so every result above is "
                    "meaningless"
                )
            else:
                note("nothing delivered, as it must not be")
        else:
            fail("negative control: the call did not complete, so nothing was proven")
        deactivate(x_id)

    print()
    if failures:
        print(f"RESULT: {len(failures)} failure(s)")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"RESULT: all {len(TARGET_TYPES)} target identifier types detected, "
        "and an unmatched warrant delivered nothing"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
