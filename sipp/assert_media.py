#!/usr/bin/env python3
"""Assert on a real media engine after a functional-test run.

One tool per engine family, because each exposes its counters differently:
siphon-rtp over Prometheus HTTP, rtpengine over NG/bencode, rtpproxy over its
classic text protocol. All of them answer the same question, which the SIPp
scenario structurally cannot: did the engine actually do the work, accept every
command, and let go of the call afterwards?

Oracles:

  metrics  — siphon-rtp's Prometheus counters. `control_errors_total` is the
             interesting one: it counts commands the engine rejected, so a call
             that completes with a non-zero value means siphon sent something
             the engine refused and the SIP leg never noticed. That is exactly
             the failure a green call flow hides. `--max-offers` is the other:
             a `reoffer` does not bump `offers_total` and a replacement `offer`
             does, so an exact count is how a caller proves a live call was
             renegotiated rather than replaced.

  ng       — rtpengine's `statistics` command over NG/bencode. Same idea via
             `rejectedsessions`. Note the two engines differ in strictness:
             rtpengine accepts an SRTP offer answered in plain RTP where
             siphon-rtp refuses it (RFC 4568 §5.1.2), so a clean run here is
             not by itself evidence the same script is clean on the other.

  rtpproxy — the classic relay's `I` counters. Narrower: no metrics endpoint
             and no rejected-command counter exist, so this can only say the
             session was created and then released.

  ws       — the AI server's `AI-WS-VERDICT` line (see mock_ai_ws.py), read
             from a log file or stdin. A verdict that never appears fails, so
             the bridge silently never being dialled is caught rather than
             passing by absence.

  cdr      — siphon's own `MEDIA` CDR records, which carry the engine's
             end-of-call per-leg counters. This is the only oracle that can say
             audio flowed *both ways between two parties*: `near_packets_in` and
             `far_packets_in` are what each leg's peer actually put on the wire,
             so requiring all four of in/out on both legs is a bidirectional
             assertion no SIP scenario and no command log can make. A record
             where one direction is zero is a connected call with one-way audio,
             which is exactly what a bridge gets wrong when it leaves an
             attachment on or re-points only one leg.

Usage:
    assert_media.py metrics --url http://172.20.0.130:9091/metrics \
        --min-offers 1 --min-deletes 1 --max-control-errors 0
    assert_media.py ng --address 172.20.0.44:22222 --min-sessions 1 --max-rejected 0
    assert_media.py rtpproxy --address 172.20.0.144:22222 --min-sessions 1
    assert_media.py cdr --path /var/log/siphon/cdr.jsonl --min-packets 20
    docker compose logs mock-ai-ws | assert_media.py ws
"""

import argparse
import json
import re
import socket
import sys
import time
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

    # A ceiling on the offers as well as a floor, because the two answer
    # different questions. `reoffer` renegotiates a live call and does not count
    # here; a replacement `offer` on that same call does. An exact expected count
    # is therefore what tells a re-negotiation apart from a replacement — the one
    # that frees the ports and drops the bridge, tee or recording riding on them,
    # and which no SIP scenario can see because both produce a re-INVITE.
    offers = metrics.get("siphon_rtp_offers_total", 0.0)
    if offers > args.max_offers:
        failures.append(
            f"siphon_rtp_offers_total={offers:g}, expected <= {args.max_offers} "
            f"— a live call was replaced rather than renegotiated"
        )

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



# ---------------------------------------------------------------------------
# Shared: settle polling
# ---------------------------------------------------------------------------


def settle(sample, deadline_secs: float):
    """Re-evaluate `sample()` until it reports no failures, or time runs out.

    Neither classic engine updates its live-session counter synchronously with
    the delete: rtpproxy in particular acknowledges `D` immediately but only
    drops `active sessions` on a later cleanup tick, so asserting the instant
    the SIPp scenario exits reads a stale 1 and fails a call that tore down
    perfectly. Polling makes the teardown assertion deterministic instead of a
    race against the engine's housekeeping. The monotonic counters
    (created/managed/rejected) are unaffected by the retry — they only ever
    grow, so a pass on the last read is a pass on every earlier one too.
    """
    end = time.monotonic() + deadline_secs
    counters, failures = sample()
    while failures and time.monotonic() < end:
        time.sleep(0.5)
        counters, failures = sample()
    return counters, failures


def report(label: str, counters: dict, failures: list) -> int:
    print(f"{label}: " + json.dumps(counters))
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    print(f"PASS: {label} within expectations")
    return 0


# ---------------------------------------------------------------------------
# rtpengine — NG/bencode `statistics`
# ---------------------------------------------------------------------------


def bencode(value) -> bytes:
    """Minimal bencode encoder — enough for `{"command": "statistics"}`."""
    if isinstance(value, dict):
        body = b"".join(bencode(k) + bencode(v) for k, v in sorted(value.items()))
        return b"d" + body + b"e"
    if isinstance(value, int):
        return b"i" + str(value).encode() + b"e"
    if isinstance(value, str):
        value = value.encode()
    if isinstance(value, bytes):
        return str(len(value)).encode() + b":" + value
    raise TypeError(f"cannot bencode {type(value).__name__}")


def bdecode(data: bytes, index: int = 0):
    """Minimal bencode decoder returning (value, next_index)."""
    kind = data[index : index + 1]
    if kind == b"d":
        index += 1
        out = {}
        while data[index : index + 1] != b"e":
            key, index = bdecode(data, index)
            val, index = bdecode(data, index)
            out[key.decode() if isinstance(key, bytes) else key] = val
        return out, index + 1
    if kind == b"l":
        index += 1
        out = []
        while data[index : index + 1] != b"e":
            item, index = bdecode(data, index)
            out.append(item)
        return out, index + 1
    if kind == b"i":
        end = data.index(b"e", index)
        return int(data[index + 1 : end]), end + 1
    colon = data.index(b":", index)
    length = int(data[index:colon])
    start = colon + 1
    return data[start : start + length], start + length


def flatten(tree, prefix="") -> dict:
    """Flatten rtpengine's nested statistics dict to dotted keys."""
    out = {}
    for key, value in tree.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, name + "."))
        elif isinstance(value, int):
            out[name] = value
    return out


def ng_command(address: str, verb: str, timeout: float) -> dict:
    """Send one NG command and return the decoded reply.

    The wire framing is `<cookie> <bencode>` — the space is load-bearing;
    without it rtpengine cannot parse the datagram and silently drops it,
    which looks exactly like the engine being down.
    """
    host, _, port = address.rpartition(":")
    cookie = b"assert "
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(cookie + bencode({"command": verb}), (host, int(port)))
        payload = sock.recv(65535)
    finally:
        sock.close()
    decoded, _ = bdecode(payload[len(cookie) :])
    return decoded


def check_ng(args: argparse.Namespace) -> int:
    """Assert on rtpengine's own `statistics` command.

    The rtpengine analogue of the siphon-rtp metrics check, for the same
    reason: a green SIP leg only proves siphon liked the answers it got.
    `rejectedsessions` is what says the engine refused something siphon sent —
    the class of defect that otherwise reads as a perfectly successful call.
    """

    def sample():
        try:
            decoded = ng_command(args.address, "statistics", args.timeout)
        except (OSError, ValueError, IndexError) as error:
            return {}, [f"could not query rtpengine at {args.address}: {error}"]
        stats = flatten(decoded.get("statistics", {}))
        counters = {
            "managedsessions": stats.get("totalstatistics.managedsessions", 0),
            "rejectedsessions": stats.get("totalstatistics.rejectedsessions", 0),
            "live": stats.get("currentstatistics.sessionstotal", 0),
        }
        failures = []
        if counters["managedsessions"] < args.min_sessions:
            failures.append(
                f"managedsessions={counters['managedsessions']}, "
                f"expected >= {args.min_sessions}"
            )
        if counters["rejectedsessions"] > args.max_rejected:
            failures.append(
                f"rejectedsessions={counters['rejectedsessions']}, expected <= "
                f"{args.max_rejected} — the engine refused a command siphon sent"
            )
        if counters["live"] > args.max_live:
            failures.append(
                f"live sessions={counters['live']}, expected <= {args.max_live} "
                f"— a call was not torn down"
            )
        return counters, failures

    counters, failures = settle(sample, args.settle_secs)
    return report("rtpengine statistics", counters, failures)


# ---------------------------------------------------------------------------
# rtpproxy — classic text protocol, `I` (info)
# ---------------------------------------------------------------------------


def check_rtpproxy(args: argparse.Namespace) -> int:
    """Assert on rtpproxy's `I` info counters.

    rtpproxy has no metrics endpoint and no rejected-command counter, so this
    oracle is narrower than the other two: sessions created, and how many are
    still active. `active sessions` back at 0 is the teardown proof — a `D`
    siphon never sent leaves the relay holding ports until its own session
    timeout, which the SIP leg cannot see.
    """
    host, _, port = args.address.rpartition(":")

    def sample():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(args.timeout)
        try:
            sock.sendto(b"assert I", (host, int(port)))
            payload = sock.recv(65535).decode("utf-8", "replace")
        except OSError as error:
            return {}, [f"could not query rtpproxy at {args.address}: {error}"]
        finally:
            sock.close()

        counters = {}
        for line in payload.split("\n"):
            line = line.strip()
            # The first line carries the echoed cookie before the counter.
            if line.startswith("assert "):
                line = line[len("assert ") :]
            name, sep, value = line.partition(":")
            if not sep:
                continue
            try:
                counters[name.strip()] = int(value.strip())
            except ValueError:
                continue

        if not counters:
            return {}, [f"no counters parsed from rtpproxy reply {payload[:160]!r}"]

        created = counters.get("sessions created", 0)
        active = counters.get("active sessions", 0)
        failures = []
        if created < args.min_sessions:
            failures.append(
                f"sessions created={created}, expected >= {args.min_sessions}"
            )
        if active > args.max_active:
            failures.append(
                f"active sessions={active}, expected <= {args.max_active} "
                f"— a call was not torn down"
            )
        return counters, failures

    counters, failures = settle(sample, args.settle_secs)
    return report("rtpproxy info", counters, failures)


# ---------------------------------------------------------------------------
# siphon's MEDIA CDR — the engine's per-leg counters, as siphon writes them out
# ---------------------------------------------------------------------------


def check_cdr(args) -> int:
    """Require one MEDIA record whose two legs each sent AND received audio.

    The engine emits a per-call summary when the media session is deleted, and
    siphon turns it into a `method: "MEDIA"` CDR carrying `near_*` / `far_*`
    packet counts. A bridged pair leaves one such record with all four counters
    up; a call whose media was only ever terminated on the engine leaves records
    with a single leg, and a half-formed bridge leaves one with a zero.

    Records are read fresh on each poll because the file is appended to as calls
    end — the summary for the bridged call is the last one written, not the
    first.
    """
    path = args.path
    floor = args.min_packets

    def sample():
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
        except OSError as error:
            return {}, [f"cannot read {path}: {error}"]

        media = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("method") == "MEDIA":
                media.append(record)

        if not media:
            return {"media_records": 0}, [
                f"no MEDIA CDR in {path} — the engine never summarised a call, "
                f"so nothing here says audio flowed"
            ]

        wanted = ["near_packets_in", "near_packets_out",
                  "far_packets_in", "far_packets_out"]
        best = None
        best_total = -1
        for record in media:
            try:
                counts = {key: int(record.get(key, 0)) for key in wanted}
            except (TypeError, ValueError):
                continue
            total = min(counts.values())
            if total > best_total:
                best_total = total
                best = counts
        if best is None:
            return {"media_records": len(media)}, [
                "every MEDIA CDR is missing the per-leg packet counters"
            ]

        counters = dict(best)
        counters["media_records"] = len(media)
        failures = [
            f"{key}={best[key]}, expected >= {floor} — "
            f"that direction carried no audio across the bridge"
            for key in wanted
            if best[key] < floor
        ]
        return counters, failures

    counters, failures = settle(sample, args.settle_secs)
    return report("media CDR", counters, failures)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)

    metrics = sub.add_parser("metrics", help="assert on the engine's Prometheus counters")
    metrics.add_argument("--url", default="http://172.20.0.130:9091/metrics")
    metrics.add_argument("--timeout", type=float, default=5.0)
    metrics.add_argument("--min-offers", type=float, default=0)
    metrics.add_argument("--max-offers", type=float, default=float("inf"))
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

    ng = sub.add_parser("ng", help="assert on rtpengine's NG statistics command")
    ng.add_argument("--address", default="172.20.0.44:22222")
    ng.add_argument("--timeout", type=float, default=5.0)
    ng.add_argument("--settle-secs", type=float, default=15.0)
    ng.add_argument("--min-sessions", type=int, default=1)
    ng.add_argument("--max-rejected", type=int, default=0)
    ng.add_argument("--max-live", type=int, default=0)
    ng.set_defaults(func=check_ng)

    rtpproxy = sub.add_parser("rtpproxy", help="assert on rtpproxy's I info counters")
    rtpproxy.add_argument("--address", default="172.20.0.144:22222")
    rtpproxy.add_argument("--timeout", type=float, default=5.0)
    rtpproxy.add_argument("--settle-secs", type=float, default=15.0)
    rtpproxy.add_argument("--min-sessions", type=int, default=1)
    rtpproxy.add_argument("--max-active", type=int, default=0)
    rtpproxy.set_defaults(func=check_rtpproxy)

    cdr = sub.add_parser("cdr", help="assert on siphon's MEDIA CDR per-leg counters")
    cdr.add_argument("--path", default="/var/log/siphon/cdr.jsonl")
    cdr.add_argument("--settle-secs", type=float, default=20.0)
    # A floor rather than "> 0": one stray packet is not audio, and the sample
    # SIPp streams is 30 ms per packet, so a couple of seconds of talking is
    # dozens either way.
    cdr.add_argument("--min-packets", type=int, default=10)
    cdr.set_defaults(func=check_cdr)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
