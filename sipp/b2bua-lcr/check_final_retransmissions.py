#!/usr/bin/env python3
"""Fail when a SIPp caller received a final response more than once.

A UAS retransmits a final response to an INVITE until the ACK for it is matched
(RFC 3261 §17.2.1, Timer G), so a final response that reaches the caller twice
means the caller's ACK was not absorbed. SIPp handles such a retransmission
itself, re-sending its ACK and counting it in the Retrans column, so a scenario
cannot branch on it. This reads that column from the screen SIPp dumps as it
quits (-trace_screen -screen_file).

Usage: check_final_retransmissions.py <screen file>
"""

import re
import sys

HEADER = "Messages  Retrans"
RECEIVED_RESPONSE = re.compile(r"^\s*(\d{3}) <-+\s+(\d+)\s+(\d+)")


def main(path):
    with open(path, encoding="utf-8", errors="replace") as screen:
        lines = screen.read().splitlines()
    headers = [index for index, line in enumerate(lines) if HEADER in line]
    if not headers:
        print(f"{path}: no message counts in the screen dump")
        return 1

    status = 0
    checked = 0
    # A dump can hold more than one screen; the last one is the final count.
    for line in lines[headers[-1] :]:
        match = RECEIVED_RESPONSE.match(line)
        if match is None or int(match.group(1)) < 200:
            continue
        code, received, retransmitted = match.group(1), int(match.group(2)), int(match.group(3))
        checked += 1
        print(f"{code}: received {received}, retransmitted {retransmitted}")
        if received == 0:
            print(f"{code}: never received")
            status = 1
        if retransmitted != 0:
            print(f"{code}: reached the caller again after its ACK, which was not absorbed")
            status = 1
    if checked == 0:
        print(f"{path}: the caller received no final response")
        return 1
    return status


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
