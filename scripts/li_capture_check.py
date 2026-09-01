#!/usr/bin/env python3
"""Per-record checks on a captured ETSI TS 103 221-2 delivery stream.

Called by scripts/validate_li_capture.sh, which does the capture and the
coarse assertions. This does the two that need arithmetic across records:

  * the RTP inside the X3 content records has **contiguous sequence numbers**,
    which is what says the packet count is right rather than merely non-zero —
    a gap is a lost packet and a repeat is a duplicated one, and either leaves a
    total looking perfectly healthy;
  * there is one content record per RTP packet the media engine relayed in the
    intercepted direction, counted from a separate capture taken in the
    engine's own network namespace.

Everything here reads tshark's output. Nothing decodes a PDU itself, on
purpose: a reader of ours would agree with our writer about a field we misread,
which is the whole reason the capture is dissected by somebody else's code.
"""

from __future__ import annotations

import argparse
import collections
import subprocess
import sys


def tshark(arguments: list[str]) -> list[str]:
    """Run tshark and return its non-empty output lines."""
    result = subprocess.run(
        ["tshark", "-q", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        # tshark writes a preferences-permission warning to stderr on a
        # confined system and still succeeds, so only a non-zero exit is a
        # failure worth reporting.
        print(f"  tshark failed: {result.stderr.strip()[:300]}", file=sys.stderr)
        return []
    return [line for line in result.stdout.splitlines() if line.strip()]


def sequence_numbers(lines: list[str]) -> list[int]:
    """Flatten tshark's per-frame fields into a list of sequence numbers.

    A frame holding several PDUs comes back as one comma-separated row.
    """
    numbers: list[int] = []
    for line in lines:
        for value in line.replace("\t", ",").split(","):
            value = value.strip()
            if value.isdigit():
                numbers.append(int(value))
    return numbers


def check_contiguous(numbers: list[int]) -> list[str]:
    """Report every gap and every repeat in an RTP sequence run.

    RTP sequence numbers are 16-bit and wrap, so the step is computed modulo
    65536 rather than by subtraction — a stream that wraps mid-call is not a
    fault and must not be reported as one.
    """
    problems: list[str] = []

    repeats = [
        number for number, count in collections.Counter(numbers).items() if count > 1
    ]
    if repeats:
        problems.append(
            f"{len(repeats)} RTP sequence number(s) delivered more than once "
            f"(first: {sorted(repeats)[:5]}) — content was duplicated"
        )

    for previous, current in zip(numbers, numbers[1:]):
        step = (current - previous) % 65536
        if step != 1:
            problems.append(
                f"RTP sequence jumped {previous} -> {current} (step {step}); "
                "content was lost or reordered on the X3 path"
            )
            # One report is enough to fail; listing every consequence of one
            # gap would bury it.
            break

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, help="the X2/X3 delivery capture")
    parser.add_argument("--dissector", required=True, help="the X2X3 Lua dissector")
    parser.add_argument("--port", required=True, help="the TCP port the delivery is on")
    parser.add_argument(
        "--rtp-capture",
        required=True,
        help="a capture taken in the media engine's namespace",
    )
    arguments = parser.parse_args()

    failures: list[str] = []

    # --- the RTP carried inside the X3 records ------------------------------
    #
    # The dissector hands an RTP payload to Wireshark's own RTP dissector, so
    # asking for `rtp.seq` here reads the sequence numbers out of the delivered
    # content — through two dissectors, neither of them ours.
    delivered = sequence_numbers(
        tshark(
            [
                "-r",
                arguments.capture,
                "-X",
                f"lua_script:{arguments.dissector}",
                "-d",
                f"tcp.port=={arguments.port},x2x3",
                "-T",
                "fields",
                "-e",
                "rtp.seq",
            ]
        )
    )

    if not delivered:
        failures.append(
            "no RTP sequence number was readable inside any X3 record; either no "
            "content was delivered or the payload is not the RTP it claims to be"
        )
    else:
        print(
            f"  RTP sequence numbers inside X3: {len(delivered)} "
            f"({delivered[0]} … {delivered[-1]})"
        )
        problems = check_contiguous(delivered)
        for problem in problems:
            failures.append(problem)
        if not problems:
            print(f"  ok   all {len(delivered)} X3 records are contiguous RTP")

    # --- against what the engine actually relayed ---------------------------
    #
    # The engine sees each packet twice, once arriving and once leaving, so the
    # relayed stream in the intercepted direction is counted by its own
    # sequence numbers rather than by frames.
    relayed = sequence_numbers(
        tshark(
            [
                "-r",
                arguments.rtp_capture,
                "-o",
                "rtp.heuristic_rtp:TRUE",
                "-T",
                "fields",
                "-e",
                "rtp.seq",
            ]
        )
    )
    unique_relayed = sorted(set(relayed))

    if not unique_relayed:
        print(
            "  note: no RTP was decodable in the engine capture, so the "
            "delivered count could not be cross-checked against it"
        )
    else:
        print(
            f"  RTP relayed by the engine: {len(unique_relayed)} distinct packets "
            f"({unique_relayed[0]} … {unique_relayed[-1]})"
        )
        missing = sorted(set(unique_relayed) - set(delivered))
        if missing:
            failures.append(
                f"{len(missing)} packet(s) the engine relayed were never delivered "
                f"as content (first: {missing[:5]}) — warranted content is missing"
            )
        else:
            print(
                f"  ok   every one of the {len(unique_relayed)} relayed packets "
                "was delivered as an X3 record"
            )

    for failure in failures:
        print(f"  FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
