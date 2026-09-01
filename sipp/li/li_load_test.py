#!/usr/bin/env python3
"""Throughput and leak behaviour with lawful interception actually switched on.

Everything else in this repo measures siphon with `lawful_intercept` absent.
The 16-row baseline does, and so does the memory-leak soak — which means the
whole interception path has never been under load: not the per-session matching,
not the X2 delivery, and not the bookkeeping that decides once per Call-ID and
has to release it again.

That gap matters more than an ordinary one. Interception is enforced in the
dispatcher, below the script, so it runs on *every* message on *every* leg of
*every* call — the hottest path in the process. And its two maps are keyed on
the Call-ID, which the peer chooses.

So this places SIPp calls, at a rate, through a node with a live warrant, and
asks two questions:

  1. **What does it cost?** Reported as calls per second with interception on,
     against the same scenario with the warrant withdrawn. A single number on
     one machine is not a benchmark, but a large gap is a finding.
  2. **Does it drain?** `siphon_li_remembered_sessions` must fall back to zero
     once the calls are over. A floor that rises with each cycle is a leak on an
     interface an attacker can drive.

Exit code is the test result.
"""

from __future__ import annotations

import os
import ssl
import subprocess
import sys
import time
import urllib.error
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

SIPHON_SIP = os.environ.get("SIPHON_SIP", "network-element:5060")
METRICS = os.environ.get("METRICS_URL", "http://network-element:9090/metrics")
UAC_SCENARIO = os.environ.get("UAC_SCENARIO", "/app/li_load_uac.xml")
CALLEE = os.environ.get("CALLEE", "callee@siphon.test")

DESTINATION_DID = "dddddddd-0000-4000-8000-00000000ffff"
TARGET_E164 = os.environ.get("TARGET_E164", "15551234567")
MDF_HOST = os.environ.get("MDF_HOST", "172.29.0.20")
MDF_PORT = int(os.environ.get("MDF_PORT", "42069"))

CALLS = int(os.environ.get("LOAD_CALLS", "6000"))
# Bounded by the called party, not by siphon.
#
# The 16-row baseline puts a proxy near 10k cps, and the temptation is to ask
# for a fraction of that here. But the callee in this profile is a *single*
# SIPp process answering every call, and it saturates first: at 3000 cps the
# calls back up behind it and the run never finishes, which measures the test
# rig rather than the element. This rate is one the rig sustains, so the run is
# about interception's behaviour under sustained call churn — thousands of
# sessions opened and closed — rather than about peak throughput, which the
# baseline already measures properly.
RATE = int(os.environ.get("LOAD_RATE", "500"))
CYCLES = int(os.environ.get("LOAD_CYCLES", "3"))
# What counts as "drained". Not zero on the nose: a call whose BYE is still in
# flight when the sample is taken is legitimately still remembered.
DRAIN_CEILING = int(os.environ.get("DRAIN_CEILING", "50"))
# A burst of thousands will lose the occasional call to the load generator's own
# timers — a 200 to a BYE arriving after SIPp has abandoned that call. Tolerated
# because this profile asks whether the element carries load and releases its
# state; whether every individual call is intercepted correctly is what
# li_x1_test.py and li_target_types_test.py assert, one call at a time.
MAX_FAILURE_RATE = float(os.environ.get("MAX_FAILURE_RATE", "0.005"))

failures: list[str] = []


def fail(message: str) -> None:
    print(f"  FAIL: {message}", flush=True)
    failures.append(message)


def note(message: str) -> None:
    print(f"  {message}", flush=True)


# --- X1 -------------------------------------------------------------------


def tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    return context


def timestamp() -> str:
    """A TS 103 280 QualifiedMicrosecondDateTime: exactly six fractional digits."""
    now = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + f".{int(now % 1 * 1_000_000):06d}Z"


def post_x1(type_name: str, payload: str) -> str:
    """One X1 request.

    The message type goes in `xsi:type` on `x1RequestMessage` inside an
    `X1Request` container — that polymorphic dispatch *is* the interface, and a
    message posted as its own root element is refused with a top-level error
    rather than a per-message one.
    """
    envelope = (
        f"<admfIdentifier>{ADMF_ID}</admfIdentifier>"
        f"<neIdentifier>{NE_ID}</neIdentifier>"
        f"<messageTimestamp>{timestamp()}</messageTimestamp>"
        f"<version>{VERSION}</version>"
        f"<x1TransactionId>{uuid.uuid4()}</x1TransactionId>"
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<X1Request xmlns="{X1}" xmlns:c="{COMMON}" xmlns:xsi="{XSI}">'
        f'<x1RequestMessage xsi:type="{type_name}">{envelope}{payload}</x1RequestMessage>'
        "</X1Request>"
    )
    request = urllib.request.Request(
        NE_URL, data=xml.encode(), headers={"Content-Type": "application/xml"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=30, context=tls_context()) as response:
            return response.read().decode()
    except urllib.error.HTTPError as error:
        return error.read().decode()
    except Exception as error:  # noqa: BLE001 - a connection problem is a result
        return f"<error>{error}</error>"


def response_kind(xml: str) -> str:
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return "unparseable"
    message = root.find(f"{{{X1}}}x1ResponseMessage")
    return message.get(f"{{{XSI}}}type", "?") if message is not None else root.tag.split("}")[-1]


def provision() -> str | None:
    # Clear anything an earlier run left, so a rerun is not refused 2030.
    post_x1("RemoveDestinationRequest", f"<dId>{DESTINATION_DID}</dId>")
    body = post_x1(
        "CreateDestinationRequest",
        "<destinationDetails>"
        f"<dId>{DESTINATION_DID}</dId>"
        "<friendlyName>load</friendlyName>"
        "<deliveryType>X2Only</deliveryType>"
        "<deliveryAddress><ipAddressAndPort>"
        f"<c:address><c:IPv4Address>{MDF_HOST}</c:IPv4Address></c:address>"
        f"<c:port><c:TCPPort>{MDF_PORT}</c:TCPPort></c:port>"
        "</ipAddressAndPort></deliveryAddress>"
        "</destinationDetails>",
    )
    if response_kind(body) != "CreateDestinationResponse":
        fail(f"CreateDestination failed: {response_kind(body)}")
        return None

    x_id = str(uuid.uuid4())
    body = post_x1(
        "ActivateTaskRequest",
        "<taskDetails>"
        f"<xId>{x_id}</xId>"
        "<targetIdentifiers><targetIdentifier>"
        f"<e164Number>{TARGET_E164}</e164Number>"
        "</targetIdentifier></targetIdentifiers>"
        "<deliveryType>X2Only</deliveryType>"
        f"<listOfDIDs><dId>{DESTINATION_DID}</dId></listOfDIDs>"
        "</taskDetails>",
    )
    if response_kind(body) != "ActivateTaskResponse":
        fail(f"ActivateTask failed: {response_kind(body)}")
        return None
    return x_id


def deactivate(x_id: str) -> None:
    post_x1("DeactivateTaskRequest", f"<xId>{x_id}</xId>")
    post_x1("RemoveDestinationRequest", f"<dId>{DESTINATION_DID}</dId>")


# --- metrics ---------------------------------------------------------------


def gauge(name: str) -> float | None:
    try:
        with urllib.request.urlopen(METRICS, timeout=10) as response:
            for line in response.read().decode().splitlines():
                if line.startswith(f"siphon_{name} "):
                    return float(line.split()[1])
    except Exception:  # noqa: BLE001 - an unreadable gauge is reported by the caller
        return None
    return None


# --- load ------------------------------------------------------------------


def run_load(label: str, target_user: str) -> float | None:
    """Place CALLS calls at RATE cps; return the achieved rate."""
    command = [
        "sipp",
        SIPHON_SIP,
        "-sf",
        UAC_SCENARIO,
        "-key",
        "to_uri",
        f"{target_user}@siphon.test",
        "-key",
        "from_user",
        "loadgen",
        "-key",
        "from_host",
        "siphon.test",
        "-m",
        str(CALLS),
        "-r",
        str(RATE),
        "-timeout",
        "120s",
        "-nostdin",
    ]
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        # Almost always the callee saturating rather than siphon: one SIPp
        # process answers every call here, so above a few hundred cps the calls
        # queue behind it and never complete. Reported rather than raised, so a
        # rig limit does not read as a stack trace.
        fail(
            f"{label}: the load run did not finish within 300s at {RATE} cps — "
            "the called party is a single SIPp process and saturates before "
            "siphon does; lower LOAD_RATE"
        )
        return None
    elapsed = time.monotonic() - started

    # SIPp exits non-zero if *any* call failed, which at this volume means a
    # single straggler fails the run. So the counts are read instead: the
    # question here is whether the element carried the load and released its
    # state, not whether every last call in a burst survived the load
    # generator's own timers.
    succeeded, failed = call_counts(result.stdout)

    if succeeded is None:
        # No counts at all means SIPp never ran — a bad invocation, which it
        # reports on stderr while exiting 255 with an empty stdout.
        note(f"    sipp exited {result.returncode}")
        if result.stderr.strip():
            note(f"    stderr: {result.stderr.strip()[-500:]}")
        fail(f"{label}: the load run did not start")
        return None

    attempted = succeeded + failed
    if attempted == 0:
        fail(f"{label}: no calls were placed")
        return None

    failure_rate = failed / attempted
    if failure_rate > MAX_FAILURE_RATE:
        note(f"    {succeeded} succeeded, {failed} failed")
        if result.stderr.strip():
            note(f"    stderr: {result.stderr.strip()[-500:]}")
        fail(
            f"{label}: {failed} of {attempted} calls failed "
            f"({failure_rate:.1%}, ceiling {MAX_FAILURE_RATE:.1%})"
        )
        return None
    if failed:
        note(f"    ({failed} of {attempted} calls failed, within tolerance)")

    rate = CALLS / elapsed if elapsed > 0 else 0.0
    note(f"    {label}: {CALLS} calls in {elapsed:.1f}s = {rate:.0f} cps")
    return rate


def call_counts(output: str) -> tuple[int | None, int]:
    """Successful and failed call counts from SIPp's summary table."""
    succeeded = None
    failed = 0
    for line in output.splitlines():
        fields = [field.strip() for field in line.split("|")]
        if len(fields) < 3:
            continue
        # The table's last column is the cumulative total.
        if fields[0].startswith("Successful call") and fields[2].isdigit():
            succeeded = int(fields[2])
        elif fields[0].startswith("Failed call") and fields[2].isdigit():
            failed = int(fields[2])
    return succeeded, failed


def main() -> int:
    print("Interception under load: what it costs, and whether it drains")
    print(f"  {CALLS} calls x {CYCLES} cycles at {RATE} cps")

    baseline_sessions = gauge("li_remembered_sessions")
    if baseline_sessions is None:
        fail(f"could not read siphon_li_remembered_sessions from {METRICS}")
        return 1
    note(f"remembered sessions at rest: {baseline_sessions:.0f}")

    # --- warm up, and throw it away ----------------------------------------
    #
    # The first burst after startup pays for everything that is lazy: the script
    # engine, the connections, the allocator's arenas. Measured, it came in at
    # 187 cps against 496 for every burst after it — which, compared against the
    # warranted runs that follow, reported interception as *165% faster* than no
    # interception. A number that wrong is worse than no number, because it
    # passes.
    print("\n[0] warming up (discarded)")
    run_load("warmup", "nobody")

    # --- with no warrant provisioned ---------------------------------------
    print("\n[1] no warrant provisioned")
    without = run_load("unwarranted", "nobody")

    # --- with a warrant that every call matches ----------------------------
    print("\n[2] a warrant every call matches")
    x_id = provision()
    if x_id is None:
        return 1
    note(f"warrant {x_id[:8]}… active on {TARGET_E164}")

    rates: list[float] = []
    for cycle in range(1, CYCLES + 1):
        rate = run_load(f"warranted cyc {cycle}/{CYCLES}", TARGET_E164)
        if rate is not None:
            rates.append(rate)

        # Let the dialogs finish before sampling, or calls still in flight
        # read as a leak.
        time.sleep(5)
        remembered = gauge("li_remembered_sessions")
        if remembered is None:
            fail("the remembered-sessions gauge stopped being readable")
            break
        note(f"    remembered sessions after cycle {cycle}: {remembered:.0f}")
        if remembered > DRAIN_CEILING:
            fail(
                f"cycle {cycle}: {remembered:.0f} sessions still remembered after the "
                f"calls ended (ceiling {DRAIN_CEILING}) — the per-session state is "
                "not being released"
            )

    deactivate(x_id)

    # --- the cost ----------------------------------------------------------
    print("\n[3] cost of interception")
    if without and rates:
        with_li = sum(rates) / len(rates)
        note(f"unwarranted: {without:.0f} cps")
        note(f"warranted:   {with_li:.0f} cps (mean of {len(rates)})")

        # What this number is, and is not.
        #
        # SIPp places calls at the rate it was asked for. If siphon meets that
        # rate in both runs then both finish at it, the delta is zero, and that
        # says only "no cost measurable at this rate" — never "no cost". A real
        # capacity comparison needs the rate pushed until something saturates,
        # and in this profile the called party is a single SIPp process, so it
        # may saturate before siphon does. Read a near-zero delta as "nothing
        # obviously wrong", and use the 16-row baseline for capacity.
        saturated = without < RATE * 0.9 or with_li < RATE * 0.9
        if not saturated:
            note(
                f"both runs met the requested {RATE} cps, so this bounds the cost "
                "rather than measuring it"
            )

        if without > 0:
            delta = (with_li - without) / without * 100.0
            note(f"delta:       {delta:+.1f}%")
            # Interception cannot make a node faster. A large positive delta
            # means the two runs were not comparable — the usual cause being an
            # unwarmed first burst — and the number must not be read as a cost.
            if delta > 25.0:
                fail(
                    f"the unwarranted run measured {abs(delta):.0f}% slower than the "
                    "warranted ones, which interception cannot cause — the runs were "
                    "not comparable, so the cost figure is meaningless"
                )
            # Not a tight gate, for the reason above. It catches a collapse,
            # which is what a mistake on this path would look like.
            if delta < -25.0:
                fail(
                    f"interception cost {abs(delta):.0f}% of throughput, which is far "
                    "more than matching a handful of warrants should cost — worth "
                    "investigating before this ships"
                )

    print()
    if failures:
        print(f"RESULT: {len(failures)} failure(s)")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("RESULT: interception carries load and its per-session state drains")
    return 0


if __name__ == "__main__":
    sys.exit(main())
