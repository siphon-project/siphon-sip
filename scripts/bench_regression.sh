#!/usr/bin/env bash
#
# bench_regression.sh — criterion perf-regression gate for the per-message SIP
# hot paths (benches/sip_hot_path.rs).
#
# Runs the criterion benches and compares each benchmark's median against the
# committed baseline in benches/baseline.json. FAILS (exit 1) if any benchmark
# is more than THRESHOLD% slower than its baseline. This is the hard gate folded
# into scripts/cut-release.sh; CI only proves the benches compile.
#
# The numbers are HARDWARE-SPECIFIC (same rule as the README throughput table) —
# run this, and re-baseline with --save, on the same machine as that table.
# If a change *improves* a number, re-baseline to lock the new floor in. Never
# raise the baseline to make a regression pass — diagnose or roll back.
#
# Usage:
#   scripts/bench_regression.sh            # run + gate against benches/baseline.json
#   scripts/bench_regression.sh --save     # run + overwrite the baseline (new floor)
#   scripts/bench_regression.sh --save-new # run + baseline only ids that have none
#
# --save-new is how a NEW bench gets its first baseline. Plain --save rewrites
# every row, which re-floors benchmarks the change never touched; that is fine
# when locking in a measured improvement and wrong when all you did was add a
# file. Set BENCH_STRICT=1 to make an unbaselined benchmark a hard failure
# rather than a warning.
#   BENCH_THRESHOLD_PCT=10 scripts/bench_regression.sh
#   BENCH_ARGS="--measurement-time 2 --warm-up-time 1" scripts/bench_regression.sh
#
# Self-contained: no critcmp/jq — the comparison reads criterion's own
# target/criterion/<id>/new/estimates.json via python3 (already a project dep).

set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

MODE="gate"
case "${1:-}" in
  --save) MODE="save" ;;
  --save-new) MODE="save-new" ;;
  "") ;;
  *) die "unknown argument: $1 (expected --save or --save-new)" ;;
esac

export BENCH_THRESHOLD_PCT="${BENCH_THRESHOLD_PCT:-10}"
export BENCH_BASELINE="benches/baseline.json"
export BENCH_CRITERION_DIR="target/criterion"
export BENCH_MODE="$MODE"

if [ "$MODE" != "save" ] && [ ! -f "$BENCH_BASELINE" ]; then
  die "no baseline at $BENCH_BASELINE — establish one first: scripts/bench_regression.sh --save"
fi

echo "==> running criterion benches (all hot-path bench targets)"
# --benches runs every [[bench]] target. The gate below iterates the BASELINE's
# ids, so a benchmark with no baseline row runs and is never compared — that is
# what let `framing/*` and `traffic_counters/*` go ungated for two releases.
# Unbaselined ids are now reported (and fail under BENCH_STRICT=1); add them
# with --save-new.
# shellcheck disable=SC2086
PYO3_PYTHON="${PYO3_PYTHON:-python3}" cargo bench --benches -- ${BENCH_ARGS:-}

echo "==> comparing against $BENCH_BASELINE (threshold ${BENCH_THRESHOLD_PCT}% slower = regression)"
python3 - <<'PYEOF'
import json, os, sys

threshold = float(os.environ["BENCH_THRESHOLD_PCT"])
baseline_path = os.environ["BENCH_BASELINE"]
crit_dir = os.environ["BENCH_CRITERION_DIR"]
mode = os.environ["BENCH_MODE"]


def point_estimate(bench_id):
    """Median nanoseconds for a benchmark id from criterion's latest run."""
    estimates = os.path.join(crit_dir, bench_id, "new", "estimates.json")
    if not os.path.isfile(estimates):
        return None
    with open(estimates) as handle:
        data = json.load(handle)
    stat = data.get("median") or data.get("mean")
    return stat["point_estimate"] if stat else None


def discover_ids():
    """Every benchmark id under target/criterion that has a fresh run."""
    found = []
    for root, _dirs, files in os.walk(crit_dir):
        if "estimates.json" in files and os.path.basename(root) == "new":
            bench_id = os.path.relpath(os.path.dirname(root), crit_dir)
            if bench_id != "report":
                found.append(bench_id)
    return sorted(found)


if mode in ("save", "save-new"):
    measured = {bid: point_estimate(bid) for bid in discover_ids()}
    measured = {bid: ns for bid, ns in measured.items() if ns is not None}
    if not measured:
        sys.exit("error: no benchmark results found to save — did the bench run?")

    if mode == "save-new":
        # Only add ids that have no row yet. Existing rows are carried over
        # untouched, so adding a bench cannot quietly re-floor its neighbours.
        existing = {}
        if os.path.isfile(baseline_path):
            with open(baseline_path) as handle:
                existing = json.load(handle)
        added = {bid: ns for bid, ns in measured.items() if bid not in existing}
        if not added:
            print(f"no unbaselined benchmarks — {baseline_path} already covers all "
                  f"{len(existing)} measured id(s)")
            sys.exit(0)
        combined = dict(existing)
        combined.update(added)
        with open(baseline_path, "w") as handle:
            json.dump(combined, handle, indent=2, sort_keys=True)
            handle.write("\n")
        print(f"added {len(added)} new benchmark(s) to {baseline_path} "
              f"({len(existing)} existing row(s) untouched)")
        for bid, ns in sorted(added.items()):
            print(f"  {bid:<28} {ns/1000:8.3f} us")
        sys.exit(0)

    with open(baseline_path, "w") as handle:
        json.dump(measured, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"saved {len(measured)} benchmarks to {baseline_path}")
    for bid, ns in sorted(measured.items()):
        print(f"  {bid:<28} {ns/1000:8.3f} us")
    sys.exit(0)

with open(baseline_path) as handle:
    baseline = json.load(handle)

regressions = []
missing = []
rows = []
for bid, base_ns in sorted(baseline.items()):
    cur_ns = point_estimate(bid)
    if cur_ns is None:
        missing.append(bid)
        continue
    delta_pct = (cur_ns - base_ns) / base_ns * 100.0
    flag = ""
    if delta_pct > threshold:
        flag = "  <== REGRESSION"
        regressions.append((bid, delta_pct))
    elif delta_pct < -threshold:
        flag = "  (improved — consider --save)"
    rows.append((bid, base_ns, cur_ns, delta_pct, flag))

def fmt_us(ns):
    return f"{ns/1000:.3f}us"

print(f"{'benchmark':<28}{'baseline':>12}{'current':>12}{'change':>10}")
for bid, base_ns, cur_ns, delta_pct, flag in rows:
    print(f"{bid:<28}{fmt_us(base_ns):>12}{fmt_us(cur_ns):>12}{delta_pct:>+9.1f}%{flag}")

if missing:
    print()
    print("warning: baseline benchmarks with no current result (renamed/removed?):")
    for bid in missing:
        print(f"  {bid}")

# The mirror image, and the one that actually bit: a benchmark that ran and has
# no baseline row is silently not gated.
unbaselined = [bid for bid in discover_ids() if bid not in baseline]
if unbaselined:
    print()
    print(f"warning: {len(unbaselined)} benchmark(s) ran with no baseline row "
          f"(not gated — add with --save-new):")
    for bid in unbaselined:
        print(f"  {bid}")

if regressions:
    print()
    print(f"FAIL: {len(regressions)} benchmark(s) regressed > {threshold:.0f}%:")
    for bid, delta_pct in regressions:
        print(f"  {bid}: {delta_pct:+.1f}%")
    print("Diagnose and fix, or roll back. Do NOT raise the baseline to go green.")
    sys.exit(1)

if unbaselined and os.environ.get("BENCH_STRICT") == "1":
    print()
    print(f"FAIL: BENCH_STRICT=1 and {len(unbaselined)} benchmark(s) have no baseline.")
    sys.exit(1)

print()
print(f"OK: no benchmark regressed more than {threshold:.0f}%.")
PYEOF
