#!/usr/bin/env python3
"""Assert on the real siphon-rtp engine after a functional-test run.

Two independent oracles, neither of which the SIPp scenario can see:

  metrics  — the engine's own Prometheus counters. `control_errors_total` is
             the interesting one: it counts commands the engine rejected, so a
             call that completes with a non-zero value means siphon sent
             something malformed and the engine papered over it. That is
             exactly the failure a green call flow hides, and it is the whole
             point of asserting on the NG shim rather than trusting the 200 OK.

  ws       — the AI server's `AI-WS-VERDICT` line (see mock_ai_ws.py), read
             from a log file or stdin. A verdict that never appears fails, so
             the bridge silently never being dialled is caught rather than
             passing by absence.

Usage:
    assert_engine.py metrics --url http://172.20.0.110:9091/metrics \
        --min-offers 1 --min-deletes 1 --max-control-errors 0
    docker compose logs mock-ai-ws | assert_engine.py ws
"""

import argparse
import json
import re
import sys
import urllib.request

VERDICT_PREFIX = "AI-WS-VERDICT "


def read_metrics(url: str, timeout: float) -> dict[str, float]:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        body = response.read().decode("utf-8", "replace")
    values: dict[str, float] = {}
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.match(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{[^}]*\})?\s+(-?[\d.eE+]+)$", line)
        if match:
            # Sum label sets so a metric split by labels still totals correctly.
            values[match.group(1)] = values.get(match.group(1), 0.0) + float(match.group(2))
    return values


def check_metrics(args: argparse.Namespace) -> int:
    try:
        metrics = read_metrics(args.url, args.timeout)
    except Exception as error:  # noqa: BLE001 — any failure to read is a test failure
        print(f"FAIL: could not read engine metrics from {args.url}: {error}")
        return 1

    if not metrics:
        print(f"FAIL: no metrics parsed from {args.url}")
        return 1

    failures: list[str] = []
    # Only offer / answer / delete bump their counters; answer_local (the
    # single-leg voice-AI verb) bumps none of them, so each caller states the
    # floors that make sense for the flow it just ran rather than inheriting a
    # default that would be wrong for half the profiles.
    checks = [
        ("siphon_rtp_offers_total", args.min_offers),
        ("siphon_rtp_answers_total", args.min_answers),
        ("siphon_rtp_deletes_total", args.min_deletes),
    ]
    for name, floor in checks:
        got = metrics.get(name, 0.0)
        if got < floor:
            failures.append(f"{name}={got:g}, expected >= {floor}")

    errors = metrics.get("siphon_rtp_control_errors_total", 0.0)
    if errors > args.max_control_errors:
        failures.append(
            f"siphon_rtp_control_errors_total={errors:g}, expected <= "
            f"{args.max_control_errors} — the engine rejected a command siphon sent"
        )

    # A session left behind after every call was deleted is a leak in the engine
    # or a delete siphon never sent. Either way the next call inherits it.
    sessions = metrics.get("siphon_rtp_sessions", 0.0)
    if sessions > args.max_sessions:
        failures.append(
            f"siphon_rtp_sessions={sessions:g}, expected <= {args.max_sessions} "
            f"— a call was not torn down"
        )

    reported = {
        key: metrics.get(key, 0.0)
        for key in (
            "siphon_rtp_offers_total",
            "siphon_rtp_answers_total",
            "siphon_rtp_deletes_total",
            "siphon_rtp_control_errors_total",
            "siphon_rtp_sessions",
        )
    }
    print("engine metrics: " + json.dumps(reported))
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print("PASS: engine metrics within expectations")
    return 0


def check_ws(args: argparse.Namespace) -> int:
    source = open(args.log, encoding="utf-8", errors="replace") if args.log else sys.stdin
    verdicts = []
    with source as handle:
        for line in handle:
            index = line.find(VERDICT_PREFIX)
            if index == -1:
                continue
            try:
                verdicts.append(json.loads(line[index + len(VERDICT_PREFIX) :].strip()))
            except ValueError:
                print(f"FAIL: unparseable verdict line: {line.strip()!r}")
                return 1

    if not verdicts:
        # Absence is the failure mode that matters most: it is what a bridge
        # that was never dialled looks like.
        print("FAIL: no AI-WS-VERDICT line found — the WebSocket bridge was never established")
        return 1

    if len(verdicts) < args.min_sessions:
        print(f"FAIL: {len(verdicts)} bridged session(s), expected >= {args.min_sessions}")
        return 1

    status = 0
    for index, verdict in enumerate(verdicts, 1):
        print(f"ws session {index}: {json.dumps(verdict)}")
        if not verdict.get("pass"):
            for failure in verdict.get("failures", ["unspecified"]):
                print(f"FAIL: session {index}: {failure}")
            status = 1
        if verdict.get("downlink_frames", 0) < args.min_downlink:
            print(
                f"FAIL: session {index}: downlink_frames="
                f"{verdict.get('downlink_frames', 0)}, expected >= {args.min_downlink} "
                f"— the AI response was never sent"
            )
            status = 1
    if status == 0:
        print(f"PASS: {len(verdicts)} bridged session(s), audio verified in both directions")
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    metrics = sub.add_parser("metrics", help="assert on the engine's Prometheus counters")
    metrics.add_argument("--url", default="http://172.20.0.110:9091/metrics")
    metrics.add_argument("--timeout", type=float, default=5.0)
    metrics.add_argument("--min-offers", type=float, default=0)
    metrics.add_argument("--min-answers", type=float, default=0)
    metrics.add_argument("--min-deletes", type=float, default=0)
    metrics.add_argument("--max-control-errors", type=float, default=0)
    metrics.add_argument("--max-sessions", type=float, default=0)
    metrics.set_defaults(func=check_metrics)

    ws = sub.add_parser("ws", help="assert on the AI server's verdict line")
    ws.add_argument("--log", help="log file to read (default: stdin)")
    ws.add_argument("--min-sessions", type=int, default=1)
    ws.add_argument("--min-downlink", type=int, default=1)
    ws.set_defaults(func=check_ws)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
