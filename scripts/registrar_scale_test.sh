#!/usr/bin/env bash
#
# registrar_scale_test.sh — what one registration costs in memory.
#
# scale_test.sh MODE=register measures how fast siphon accepts a REGISTER.
# This measures what it costs to *hold* the binding: register a population of
# unique AoRs, let the allocator settle, and report the marginal bytes per
# binding over an idle baseline taken from the same process.
#
# The instrument is jemalloc's own `stats.allocated` (live bytes), read off the
# Prometheus gauge, NOT RSS. That is deliberate and it is the whole reason this
# script exists rather than a `ps` one-liner: RSS on this workload is
# THP-sensitive and moves with the allocator's decay window, so the same
# unchanged binary reads double-digit percentages apart between runs, while
# `allocated` reproduces inside ~1%. RSS and jemalloc `resident` are reported
# alongside as context, never gated on.
#
# Usage:
#   scripts/registrar_scale_test.sh                    # 100k bindings @ 10k cps
#   scripts/registrar_scale_test.sh 600000 20000       # <bindings> <cps>
#   BUDGET_BYTES=2600 scripts/registrar_scale_test.sh  # gate on bytes/binding
#   TRANSPORT=tcp scripts/registrar_scale_test.sh
#   SIPHON_BIN=/tmp/siphon-a scripts/registrar_scale_test.sh   # A/B a prebuilt arm
#   _RJEM_MALLOC_CONF=narenas:4 scripts/registrar_scale_test.sh  # A/B allocator conf
#
# Report both `allocated` (live data) and `resident`, because they answer
# different questions: `allocated` is what the data structures cost and is what
# a code change moves; `resident` is what the box pays, and the gap between them
# is the allocator's, not the registrar's. Reading only one of the two is how a
# fragmentation problem gets misfiled as a struct-layout problem, and vice versa.

set -euo pipefail

BINDINGS=${1:-100000}
CPS=${2:-10000}
# Longer than RFC 3261 Timer J (64*T1 = 32 s), which is how long a completed
# non-INVITE server transaction is retained to absorb retransmissions. Settle
# for less and every REGISTER of the run is still in the transaction store at
# measurement time, and its cost is charged to the binding: at 20k bindings a
# 10 s settle reads ~7.0 KB/binding against ~2.4 KB once the store has drained.
SETTLE_SECS=${SETTLE_SECS:-45}
BUDGET_BYTES=${BUDGET_BYTES:-0}       # 0 = report only, no gate
ADMIN_PORT="${ADMIN_PORT:-8890}"
TRANSPORT="${TRANSPORT:-udp}"
PROXY="127.0.0.1:5060"
UAC_IP="127.0.0.51"
UAC_PORT=5062

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Scoped to what this script started, by PID and by scenario name. A blanket
# `pkill -f target/release/siphon` would take out a concurrent run in another
# worktree on the same box, and this measurement wants a quiet box anyway.
SIPHON_PID=""
cleanup() {
    pkill -f "register_unique_aor" 2>/dev/null || true
    [ -n "$SIPHON_PID" ] && kill -9 "$SIPHON_PID" 2>/dev/null
    return 0
}
trap cleanup EXIT

case "$TRANSPORT" in
    udp) SIPP_T="u1" ;;
    tcp) SIPP_T="t1" ;;
    *) echo "FAIL: bad TRANSPORT='$TRANSPORT' (udp|tcp)"; exit 1 ;;
esac

# Free-threaded Python, same detection as mem_leak_test.sh / scale_test.sh —
# without it the run is GIL-limited, which changes the thread picture and so
# the fixed part of the memory baseline.
if [ -z "${PYO3_PYTHON:-}" ]; then
    UV_FT_BIN=""
    if command -v uv > /dev/null 2>&1; then
        for cand in "$HOME/.local/share/uv/python/cpython-3.14"*"+freethreaded"*"/bin/python3.14t"; do
            [ -x "$cand" ] && { UV_FT_BIN="$cand"; break; }
        done
    fi
    if [ -n "$UV_FT_BIN" ]; then
        export PYO3_PYTHON="$UV_FT_BIN"; echo "[*] Using free-threaded Python: $PYO3_PYTHON"
    else
        export PYO3_PYTHON="python3"; echo "[!] WARN: free-threaded Python not found — GIL-limited run"
    fi
fi
if [ -x "$PYO3_PYTHON" ] && [ -f "$PYO3_PYTHON" ]; then
    PY_LIB_DIR="$(dirname "$(dirname "$(readlink -f "$PYO3_PYTHON")")")/lib"
    [ -d "$PY_LIB_DIR" ] && case ":${LD_LIBRARY_PATH:-}:" in
        *":$PY_LIB_DIR:"*) ;; *) export LD_LIBRARY_PATH="${PY_LIB_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
    esac
fi

command -v sipp > /dev/null 2>&1 || { echo "FAIL: sipp not on PATH"; exit 1; }

echo "=== SIPhon Registrar Scale (memory per binding) ==="
echo "  Bindings: $BINDINGS @ $CPS cps over $TRANSPORT   Settle: ${SETTLE_SECS}s (> Timer J)"
[ "$BUDGET_BYTES" -gt 0 ] && echo "  Gate: <= ${BUDGET_BYTES} bytes/binding"
echo ""

# SIPHON_BIN lets an A/B run alternate two prebuilt binaries without a rebuild
# between arms — which matters, because the arms have to be interleaved and
# repeated: a first run after idle reads high, so one A-then-B pair is not a
# result. Build both first, then alternate.
SIPHON_BIN="${SIPHON_BIN:-}"
if [ -z "$SIPHON_BIN" ]; then
    echo "[*] Building siphon (release)..."
    if ! cargo build --release --quiet > /tmp/siphon_regscale_build.log 2>&1; then
        echo "FAIL: cargo build failed"; tail -40 /tmp/siphon_regscale_build.log; exit 1
    fi
    SIPHON_BIN="./target/release/siphon"
    echo "[+] build ok"
else
    [ -x "$SIPHON_BIN" ] || { echo "FAIL: SIPHON_BIN='$SIPHON_BIN' is not executable"; exit 1; }
    echo "[*] Using prebuilt binary: $SIPHON_BIN"
fi

# No-auth REGISTER handling, derived from proxy_default.py by removing the
# digest guard — same derivation scale_test.sh MODE=register uses, so the two
# harnesses cannot drift into measuring different scripts.
CONFIG_FILE="/tmp/siphon_regscale.yaml"
SCRIPT_FILE="/tmp/siphon_regscale.py"
sed '/auth.require_digest(request, realm=DOMAIN)/,+1d' scripts/proxy_default.py > "$SCRIPT_FILE"
if grep -q "require_digest" "$SCRIPT_FILE"; then
    echo "FAIL: could not strip the digest guard from proxy_default.py"; exit 1
fi
sed "s|scripts/proxy_default.py|$SCRIPT_FILE|" siphon.yaml > "$CONFIG_FILE"
# The admin API rather than the Prometheus endpoint: /admin/metrics.json calls
# update_memory_stats() on the request, so a reading is current. The Prometheus
# gauges are only refreshed on the dispatcher's 30 s cleanup tick, which would
# make every figure here a function of when the settle happened to land.
printf '\nadmin:\n  listen: "127.0.0.1:%s"\n' "$ADMIN_PORT" >> "$CONFIG_FILE"

sleep 1
RUST_LOG="${RUST_LOG:-warn}" "$SIPHON_BIN" -c "$CONFIG_FILE" > /tmp/siphon_regscale.log 2>&1 &
SIPHON_PID=$!
sleep 2
kill -0 "$SIPHON_PID" 2>/dev/null || { echo "FAIL: siphon did not start"; cat /tmp/siphon_regscale.log; exit 1; }
for _ in $(seq 1 15); do curl -s "http://127.0.0.1:${ADMIN_PORT}/admin/health" > /dev/null 2>&1 && break; sleep 1; done
curl -s "http://127.0.0.1:${ADMIN_PORT}/admin/health" > /dev/null 2>&1 || { echo "FAIL: admin API :${ADMIN_PORT} down"; exit 1; }

# One snapshot, several fields: taking them from a single response keeps the
# reading internally consistent (registrations and allocated bytes from the same
# instant) rather than from successive scrapes.
snapshot() { curl -s "http://127.0.0.1:${ADMIN_PORT}/admin/metrics.json" 2>/dev/null; }
field() { python3 -c "
import json,sys
d=json.loads(sys.stdin.read() or '{}')
for k in sys.argv[1].split('.'):
    d = (d or {}).get(k)
print(int(d or 0))" "$1"; }
read_rss()   { awk '/^VmRSS:/ {print $2 * 1024}' "/proc/$SIPHON_PID/status" 2>/dev/null; }
read_threads() { awk '/^Threads:/ {print $2}' "/proc/$SIPHON_PID/status" 2>/dev/null; }
mb() { python3 -c "import sys; print(f'{int(sys.argv[1])/1048576:.1f}')" "$1"; }

# Warm up the script pool and the metrics path before the baseline, so the
# baseline is a running process rather than a cold one — otherwise the first
# few thousand registrations are charged for the pool's own growth.
# A distinct AoR prefix: sipp restarts [call_number] at 1 for each run, so a
# warm-up sharing the prefix would have the measured run re-register its AoRs
# instead of adding to them, and the population would come up short.
sipp -sf sipp/register_unique_aor.xml "$PROXY" -m 200 -r 200 -t "$SIPP_T" \
    -i "$UAC_IP" -p "$UAC_PORT" -s warm -fd 1 > /dev/null 2>&1 || true
while pgrep -f "register_unique_aor" > /dev/null 2>&1; do sleep 1; done
echo "[+] siphon up (PID $SIPHON_PID), warm"

echo "[*] Settling ${SETTLE_SECS}s for the idle baseline ..."
sleep "$SETTLE_SECS"
BASE=$(snapshot)
BASE_ALLOC=$(echo "$BASE" | field memory.allocated)
BASE_RESIDENT=$(echo "$BASE" | field memory.resident)
BASE_METADATA=$(echo "$BASE" | field memory.metadata)
BASE_REGS=$(echo "$BASE" | field registrations_active)
BASE_TXNS=$(echo "$BASE" | field sip.transactions_active)
BASE_RSS=$(read_rss)
THREADS=$(read_threads)
echo "[=] idle baseline: allocated=$(mb "$BASE_ALLOC") MB  resident=$(mb "$BASE_RESIDENT") MB" \
     "metadata=$(mb "$BASE_METADATA") MB  RSS=$(mb "$BASE_RSS") MB  threads=$THREADS  registrations=$BASE_REGS"
echo ""

echo "[*] Registering $BINDINGS unique AoRs at $CPS cps ..."
START=$(date +%s)
sipp -sf sipp/register_unique_aor.xml "$PROXY" -m "$BINDINGS" -r "$CPS" -t "$SIPP_T" \
    -i "$UAC_IP" -p "$UAC_PORT" -s u -trace_stat -stf /tmp/regscale_uac.csv -fd 1 \
    > /tmp/siphon_regscale_sipp.log 2>&1 || true
while pgrep -f "register_unique_aor" > /dev/null 2>&1; do sleep 1; done
ELAPSED=$(( $(date +%s) - START ))
FAILED=$(tail -1 /tmp/regscale_uac.csv 2>/dev/null | awk -F';' '{print $18+0}')
FAILED=${FAILED:-0}
echo "[+] load done in ${ELAPSED}s, ${FAILED} failed"

echo "[*] Settling ${SETTLE_SECS}s ..."
sleep "$SETTLE_SECS"
FIN=$(snapshot)
FIN_ALLOC=$(echo "$FIN" | field memory.allocated)
FIN_RESIDENT=$(echo "$FIN" | field memory.resident)
FIN_METADATA=$(echo "$FIN" | field memory.metadata)
FIN_REGS=$(echo "$FIN" | field registrations_active)
FIN_TXNS=$(echo "$FIN" | field sip.transactions_active)
FIN_RSS=$(read_rss)

HELD=$(( ${FIN_REGS:-0} - ${BASE_REGS:-0} ))
echo ""
echo "--- Results ---"
printf "  registrations_active: %s → %s  (+%s of %s registered)\n" "$BASE_REGS" "$FIN_REGS" "$HELD" "$BINDINGS"
printf "  transactions_active:  %s → %s  (must return to baseline, else the\n" "$BASE_TXNS" "$FIN_TXNS"
printf "                                  transaction store is billed to the bindings)\n"
printf "  jemalloc allocated:   %s → %s MB   (Δ %s MB)\n" \
    "$(mb "$BASE_ALLOC")" "$(mb "$FIN_ALLOC")" "$(mb $(( FIN_ALLOC - BASE_ALLOC )))"
printf "  jemalloc resident:    %s → %s MB   (Δ %s MB)\n" \
    "$(mb "$BASE_RESIDENT")" "$(mb "$FIN_RESIDENT")" "$(mb $(( FIN_RESIDENT - BASE_RESIDENT )))"
printf "  jemalloc metadata:    %s → %s MB\n" "$(mb "$BASE_METADATA")" "$(mb "$FIN_METADATA")"
printf "  process RSS:          %s → %s MB   (Δ %s MB, context only)\n" \
    "$(mb "$BASE_RSS")" "$(mb "$FIN_RSS")" "$(mb $(( FIN_RSS - BASE_RSS )))"

STATUS=0
if [ "$HELD" -le 0 ]; then
    echo "=== FAIL: the registrar holds no more bindings than it did at baseline ==="
    exit 1
fi

PER_ALLOC=$(( (FIN_ALLOC - BASE_ALLOC) / HELD ))
PER_RESIDENT=$(( (FIN_RESIDENT - BASE_RESIDENT) / HELD ))
PER_RSS=$(( (FIN_RSS - BASE_RSS) / HELD ))
echo ""
printf "  bytes/binding (allocated, the gated figure): %s\n" "$PER_ALLOC"
printf "  bytes/binding (resident):                    %s\n" "$PER_RESIDENT"
printf "  bytes/binding (RSS, noisy):                  %s\n" "$PER_RSS"
echo ""

# A dropped REGISTER is a smaller population against the same allocator noise,
# so it inflates bytes/binding rather than showing up as a memory result. Gate
# on it.
[ "$FAILED" -ne 0 ] && { echo "=== FAIL: $FAILED failed registrations ==="; STATUS=1; }
if [ "${FIN_TXNS:-0}" -gt "${BASE_TXNS:-0}" ]; then
    echo "=== FAIL: transaction store did not drain ($BASE_TXNS → $FIN_TXNS) — raise SETTLE_SECS above Timer J ==="
    STATUS=1
fi
if [ "$HELD" -ne "$BINDINGS" ]; then
    echo "=== FAIL: registered $BINDINGS but the store holds $HELD ==="
    STATUS=1
fi
if [ "$BUDGET_BYTES" -gt 0 ] && [ "$PER_ALLOC" -gt "$BUDGET_BYTES" ]; then
    echo "=== FAIL: ${PER_ALLOC} bytes/binding exceeds the ${BUDGET_BYTES} budget ==="
    STATUS=1
fi
[ "$STATUS" -eq 0 ] && echo "=== PASS: $HELD bindings held, ${PER_ALLOC} bytes/binding, 0 failed ==="
exit $STATUS
