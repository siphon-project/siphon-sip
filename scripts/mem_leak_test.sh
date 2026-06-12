#!/usr/bin/env bash
#
# SIPhon memory-leak regression test
#
# Validates that proxy/B2BUA call handling does not leak memory, using siphon's
# own Prometheus gauges as the precise signal (RSS is too noisy — jemalloc
# retains freed pages, so RSS sits above live bytes).  Two criteria:
#
#   1. siphon_proxy_dialog_sessions returns to 0 after each burst+idle cycle.
#      This is the `by_dialog_key` structure that leaked one cloned INVITE per
#      answered call (orphaned on the 2xx-ACK path, never swept).  It must
#      drain to zero once the ACK window (transaction timeout) has elapsed.
#
#   2. siphon_memory_allocated_bytes (jemalloc live bytes) does not grow across
#      cycles beyond ALLOC_BUDGET_MB.  Unlike RSS this excludes allocator
#      retention/fragmentation, so steady growth here is a real leak.
#
# The idle gap must exceed the transaction timeout + sweep interval (~62 s) so
# completed-call state is reclaimed before each measurement — hence the 65 s
# default.  To see this FAIL on the pre-fix code, run against an older commit.
#
# Usage:
#   ./scripts/mem_leak_test.sh [cycles] [calls_per_cycle] [cps] [idle_secs]
#
# Env:
#   ALLOC_BUDGET_MB — max tolerated jemalloc-allocated growth (default 8)
#   MODE            — proxy (default) | b2bua
#   TRANSPORT       — udp (default) | tcp
#   METRICS_PORT    — Prometheus port for the temp config (default 8889)

set -euo pipefail

CYCLES=${1:-4}
CALLS_PER_CYCLE=${2:-3000}
CPS=${3:-1000}
IDLE_SECS=${4:-65}
ALLOC_BUDGET_MB=${ALLOC_BUDGET_MB:-8}
METRICS_PORT="${METRICS_PORT:-8889}"
PROXY="127.0.0.1:5060"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cd "$SCRIPT_DIR"

cleanup() {
    pkill -f "invite_uac" 2>/dev/null || true
    pkill -f "invite_uas" 2>/dev/null || true
    pkill -9 -f "target/release/siphon" 2>/dev/null || true
}
trap cleanup EXIT

# --- Pick free-threaded Python 3.14t for a faithful repro ---
if [ -z "${PYO3_PYTHON:-}" ]; then
    UV_FT_BIN=""
    if command -v uv > /dev/null 2>&1; then
        for cand in "$HOME/.local/share/uv/python/cpython-3.14"*"+freethreaded"*"/bin/python3.14t"; do
            [ -x "$cand" ] && { UV_FT_BIN="$cand"; break; }
        done
    fi
    if [ -n "$UV_FT_BIN" ] && [ -x "$UV_FT_BIN" ]; then
        export PYO3_PYTHON="$UV_FT_BIN"
        echo "[*] Using free-threaded Python: $PYO3_PYTHON"
    else
        export PYO3_PYTHON="python3"
        echo "[!] WARN: free-threaded Python not found — leak magnitude will differ from prod."
    fi
fi
if [ -x "$PYO3_PYTHON" ] && [ -f "$PYO3_PYTHON" ]; then
    PYO3_PYTHON_REAL="$(readlink -f "$PYO3_PYTHON")"
    PY_LIB_DIR="$(dirname "$(dirname "$PYO3_PYTHON_REAL")")/lib"
    if [ -d "$PY_LIB_DIR" ]; then
        case ":${LD_LIBRARY_PATH:-}:" in
            *":$PY_LIB_DIR:"*) ;;
            *) export LD_LIBRARY_PATH="${PY_LIB_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
        esac
    fi
fi

echo "=== SIPhon Memory-Leak Test ==="
echo "  Cycles:          $CYCLES"
echo "  Calls/cycle:     $CALLS_PER_CYCLE @ $CPS cps"
echo "  Idle gap:        ${IDLE_SECS}s  (> transaction timeout + sweep interval)"
echo "  Alloc budget:    ${ALLOC_BUDGET_MB} MB jemalloc-allocated growth across cycles"
echo ""

echo "[*] Building siphon (release)..."
if ! cargo build --release --quiet > /tmp/siphon_leak_build.log 2>&1; then
    echo "FAIL: cargo build failed"
    tail -40 /tmp/siphon_leak_build.log
    exit 1
fi
echo "[+] build ok"

# --- Temp config (copy + Prometheus metrics enabled for the gauge checks) ---
MODE="${MODE:-proxy}"
CONFIG_FILE="/tmp/siphon_leak_${MODE}.yaml"
case "$MODE" in
    proxy) cp siphon.yaml "$CONFIG_FILE" ;;
    b2bua) sed 's|scripts/proxy_default.py|scripts/b2bua_default.py|' siphon.yaml > "$CONFIG_FILE" ;;
    *) echo "FAIL: unknown MODE='$MODE'"; exit 1 ;;
esac
printf '\nmetrics:\n  prometheus:\n    listen: "127.0.0.1:%s"\n    path: "/metrics"\n' "$METRICS_PORT" >> "$CONFIG_FILE"

TRANSPORT="${TRANSPORT:-udp}"
case "$TRANSPORT" in
    udp) SIPP_T="u1" ;;
    tcp) SIPP_T="t1" ;;
    *) echo "FAIL: unknown TRANSPORT='$TRANSPORT'"; exit 1 ;;
esac
echo "[*] Mode: $MODE  Transport: $TRANSPORT  Metrics: :$METRICS_PORT"

cleanup
sleep 1
RUST_LOG="${RUST_LOG:-warn}" PYO3_PYTHON="$PYO3_PYTHON" LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
    ./target/release/siphon -c "$CONFIG_FILE" > /tmp/siphon_leak_proxy.log 2>&1 &
SIPHON_PID=$!
sleep 2
if ! kill -0 $SIPHON_PID 2>/dev/null; then
    echo "FAIL: siphon did not start"
    cat /tmp/siphon_leak_proxy.log
    exit 1
fi

# Wait for the metrics endpoint to come up.
for _ in $(seq 1 10); do
    if curl -s "http://127.0.0.1:${METRICS_PORT}/metrics" > /dev/null 2>&1; then break; fi
    sleep 1
done
if ! curl -s "http://127.0.0.1:${METRICS_PORT}/metrics" > /dev/null 2>&1; then
    echo "FAIL: metrics endpoint :${METRICS_PORT} not responding"
    exit 1
fi
echo "[+] siphon started (PID $SIPHON_PID), metrics up"

UAS_IP="127.0.0.2"; UAC_IP="127.0.0.51"; UAS_PORT=5061; UAC_PORT=5062
sipp -sf sipp/register.xml "$PROXY" -m 1 -t "$SIPP_T" -i "$UAS_IP" -p "$UAS_PORT" \
    -s bob1 -au bob1 -ap secret > /tmp/siphon_leak_register.log 2>&1 || true
if ! grep -q "Successful call.*1" /tmp/siphon_leak_register.log; then
    echo "FAIL: registration of bob1 failed"; cat /tmp/siphon_leak_register.log; exit 1
fi
sipp -sf sipp/invite_uas_fast.xml -t "$SIPP_T" -i "$UAS_IP" -p "$UAS_PORT" -bg > /dev/null 2>&1 || true
sleep 1
echo "[+] bob1 registered, UAS up"

read_gauge() { curl -s "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | awk -v m="siphon_$1" '$1==m {print $2}'; }
read_rss_mb() { awk '/^VmRSS:/ {printf "%d", $2/1024}' "/proc/$SIPHON_PID/status" 2>/dev/null; }

fire_burst() {
    sipp -sf sipp/invite_uac_fast.xml "$PROXY" \
        -m "$CALLS_PER_CYCLE" -r "$CPS" -t "$SIPP_T" \
        -i "$UAC_IP" -p "$UAC_PORT" -s bob1 \
        -trace_stat -stf "/tmp/siphon_leak_uac.csv" -fd 1 > /dev/null 2>&1 || true
    while pgrep -f "invite_uac_fast.xml" > /dev/null 2>&1; do sleep 1; done
}

echo ""
echo "--- Warm-up burst, then idle ${IDLE_SECS}s ---"
fire_burst
sleep "$IDLE_SECS"
ALLOC_BASE=$(read_gauge memory_allocated_bytes)
DIALOG_BASE=$(read_gauge proxy_dialog_sessions)
echo "[=] post-warmup baseline: allocated=$((ALLOC_BASE / 1048576)) MB  dialog_sessions=$DIALOG_BASE  rss=$(read_rss_mb) MB"
echo ""

FAILED_TOTAL=0
LEAK_DETECTED=0
echo "--- Steady-state cycles ---"
for cycle in $(seq 1 "$CYCLES"); do
    fire_burst
    if [ -f /tmp/siphon_leak_uac.csv ]; then
        f=$(tail -1 /tmp/siphon_leak_uac.csv | awk -F';' '{print $18+0}')
        FAILED_TOTAL=$((FAILED_TOTAL + f))
    fi
    sleep "$IDLE_SECS"
    alloc=$(read_gauge memory_allocated_bytes)
    dialog=$(read_gauge proxy_dialog_sessions)
    rss=$(read_rss_mb)
    alloc_growth=$(( (alloc - ALLOC_BASE) / 1048576 ))
    # The dialog-key structure MUST drain to zero after the ACK window.
    if [ "${dialog:-0}" -ne 0 ]; then LEAK_DETECTED=1; fi
    printf "  cycle %d/%d: allocated=%d MB (Δ%+d MB)  dialog_sessions=%s  rss=%d MB  failed=%d\n" \
        "$cycle" "$CYCLES" "$((alloc / 1048576))" "$alloc_growth" "${dialog:-?}" "$rss" "${f:-0}"
done

ALLOC_FINAL=$(read_gauge memory_allocated_bytes)
DIALOG_FINAL=$(read_gauge proxy_dialog_sessions)
ALLOC_GROWTH_MB=$(( (ALLOC_FINAL - ALLOC_BASE) / 1048576 ))

echo ""
echo "--- Results ---"
echo "  jemalloc allocated:  $((ALLOC_BASE / 1048576)) MB → $((ALLOC_FINAL / 1048576)) MB  (Δ ${ALLOC_GROWTH_MB} MB, budget ${ALLOC_BUDGET_MB})"
echo "  dialog_sessions:     baseline=$DIALOG_BASE  final=$DIALOG_FINAL  (must be 0 after idle)"
echo "  Failed calls:        $FAILED_TOTAL"
echo ""

STATUS=0
if [ "$FAILED_TOTAL" -ne 0 ]; then
    echo "=== FAIL: $FAILED_TOTAL call(s) failed — correctness invariant violated ==="; STATUS=1
fi
if [ "$LEAK_DETECTED" -ne 0 ] || [ "${DIALOG_FINAL:-1}" -ne 0 ]; then
    echo "=== FAIL: siphon_proxy_dialog_sessions did not drain to 0 — dialog-key leak ==="; STATUS=1
fi
if [ "$ALLOC_GROWTH_MB" -gt "$ALLOC_BUDGET_MB" ]; then
    echo "=== FAIL: jemalloc-allocated grew ${ALLOC_GROWTH_MB} MB across ${CYCLES} cycles (> ${ALLOC_BUDGET_MB} MB) — leak ==="; STATUS=1
fi
if [ "$STATUS" -eq 0 ]; then
    echo "=== PASS: dialog_sessions drains to 0, jemalloc-allocated flat (+${ALLOC_GROWTH_MB} MB), 0 failed ==="
fi
exit $STATUS
