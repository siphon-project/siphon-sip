#!/usr/bin/env bash
#
# SIPhon memory-leak regression test
#
# Validates that SIP handling does not leak memory, using siphon's own
# Prometheus gauges as the signal (RSS is too noisy — jemalloc retains freed
# pages). It drives several workloads ("scenarios") through proxy/B2BUA and,
# for each, checks that memory returns to a flat baseline across burst+idle
# cycles. Two leak signals are gated, because siphon has two allocators:
#
#   * siphon_memory_allocated_bytes   — jemalloc live bytes (the RUST side:
#     transactions, sessions, dialog keys, message clones, …).
#   * siphon_python_allocated_blocks  — CPython's own allocator (the PYTHON
#     side: script objects, leaked Py<> refs) which jemalloc cannot see.
#
# Plus siphon_proxy_dialog_sessions must drain to 0, and every call must
# succeed. The idle gap must exceed the transaction timeout + sweep interval
# (~62 s) so completed-call state is reclaimed before each measurement.
#
# Scenarios (extend freely — each just needs a *_burst function):
#   invite    — INVITE → 200 → ACK → BYE → 200 (proxy/B2BUA call path)
#   register  — auth'd REGISTER churn (registrar + REGISTER dispatch path)
#
# NOTE on coverage: this drives the core dispatch/proxy/registrar paths. It
# does NOT yet exercise feature-specific stores that require a script using
# them (subscribe_state, registrar.on_change handlers, diameter, rtpengine),
# nor SUBSCRIBE/MESSAGE relay — those are future scenarios/scripts.
#
# Usage:
#   ./scripts/mem_leak_test.sh [cycles] [calls_per_cycle] [cps] [idle_secs]
#
# Env: ALLOC_BUDGET_MB (default 8), PYBLOCKS_BUDGET (default 50000),
#      MODE (proxy|b2bua), TRANSPORT (udp|tcp), METRICS_PORT (8889)

set -euo pipefail

CYCLES=${1:-3}
CALLS_PER_CYCLE=${2:-3000}
CPS=${3:-1000}
IDLE_SECS=${4:-65}
ALLOC_BUDGET_MB=${ALLOC_BUDGET_MB:-8}
PYBLOCKS_BUDGET=${PYBLOCKS_BUDGET:-50000}
METRICS_PORT="${METRICS_PORT:-8889}"
PROXY="127.0.0.1:5060"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCRIPT_DIR"

cleanup() {
    pkill -f "invite_uac" 2>/dev/null || true
    pkill -f "invite_uas" 2>/dev/null || true
    pkill -f "register.xml" 2>/dev/null || true
    pkill -9 -f "target/release/siphon" 2>/dev/null || true
}
trap cleanup EXIT

# --- Free-threaded Python 3.14t ---
if [ -z "${PYO3_PYTHON:-}" ]; then
    UV_FT_BIN=""
    if command -v uv > /dev/null 2>&1; then
        for cand in "$HOME/.local/share/uv/python/cpython-3.14"*"+freethreaded"*"/bin/python3.14t"; do
            [ -x "$cand" ] && { UV_FT_BIN="$cand"; break; }
        done
    fi
    if [ -n "$UV_FT_BIN" ] && [ -x "$UV_FT_BIN" ]; then
        export PYO3_PYTHON="$UV_FT_BIN"; echo "[*] Using free-threaded Python: $PYO3_PYTHON"
    else
        export PYO3_PYTHON="python3"; echo "[!] WARN: free-threaded Python not found."
    fi
fi
if [ -x "$PYO3_PYTHON" ] && [ -f "$PYO3_PYTHON" ]; then
    PY_LIB_DIR="$(dirname "$(dirname "$(readlink -f "$PYO3_PYTHON")")")/lib"
    [ -d "$PY_LIB_DIR" ] && case ":${LD_LIBRARY_PATH:-}:" in
        *":$PY_LIB_DIR:"*) ;; *) export LD_LIBRARY_PATH="${PY_LIB_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
    esac
fi

echo "=== SIPhon Memory-Leak Test ==="
echo "  Cycles/scenario: $CYCLES   Calls/cycle: $CALLS_PER_CYCLE @ $CPS cps   Idle: ${IDLE_SECS}s"
echo "  Budgets: jemalloc +${ALLOC_BUDGET_MB} MB, python +${PYBLOCKS_BUDGET} blocks"
echo ""

echo "[*] Building siphon (release)..."
if ! cargo build --release --quiet > /tmp/siphon_leak_build.log 2>&1; then
    echo "FAIL: cargo build failed"; tail -40 /tmp/siphon_leak_build.log; exit 1
fi
echo "[+] build ok"

MODE="${MODE:-proxy}"
CONFIG_FILE="/tmp/siphon_leak_${MODE}.yaml"
case "$MODE" in
    proxy) cp siphon.yaml "$CONFIG_FILE" ;;
    b2bua) sed 's|scripts/proxy_default.py|scripts/b2bua_default.py|' siphon.yaml > "$CONFIG_FILE" ;;
    *) echo "FAIL: unknown MODE='$MODE'"; exit 1 ;;
esac
printf '\nmetrics:\n  prometheus:\n    listen: "127.0.0.1:%s"\n    path: "/metrics"\n' "$METRICS_PORT" >> "$CONFIG_FILE"

TRANSPORT="${TRANSPORT:-udp}"
case "$TRANSPORT" in udp) SIPP_T="u1" ;; tcp) SIPP_T="t1" ;; *) echo "FAIL: bad TRANSPORT"; exit 1 ;; esac
echo "[*] Mode: $MODE  Transport: $TRANSPORT  Metrics: :$METRICS_PORT"

cleanup; sleep 1
RUST_LOG="${RUST_LOG:-warn}" PYO3_PYTHON="$PYO3_PYTHON" LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
    ./target/release/siphon -c "$CONFIG_FILE" > /tmp/siphon_leak_proxy.log 2>&1 &
SIPHON_PID=$!
sleep 2
kill -0 $SIPHON_PID 2>/dev/null || { echo "FAIL: siphon did not start"; cat /tmp/siphon_leak_proxy.log; exit 1; }
for _ in $(seq 1 10); do curl -s "http://127.0.0.1:${METRICS_PORT}/metrics" > /dev/null 2>&1 && break; sleep 1; done
curl -s "http://127.0.0.1:${METRICS_PORT}/metrics" > /dev/null 2>&1 || { echo "FAIL: metrics :${METRICS_PORT} down"; exit 1; }
echo "[+] siphon started (PID $SIPHON_PID), metrics up"

UAS_IP="127.0.0.2"; UAC_IP="127.0.0.51"; UAS_PORT=5061; UAC_PORT=5062
sipp -sf sipp/register.xml "$PROXY" -m 1 -t "$SIPP_T" -i "$UAS_IP" -p "$UAS_PORT" -s bob1 -au bob1 -ap secret > /tmp/siphon_leak_register.log 2>&1 || true
grep -q "Successful call.*1" /tmp/siphon_leak_register.log || { echo "FAIL: register bob1"; cat /tmp/siphon_leak_register.log; exit 1; }
sipp -sf sipp/invite_uas_fast.xml -t "$SIPP_T" -i "$UAS_IP" -p "$UAS_PORT" -bg > /dev/null 2>&1 || true
sleep 1
echo "[+] bob1 registered, UAS up"

read_gauge() { curl -s "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | awk -v m="siphon_$1" '$1==m {print $2}'; }

# --- Scenario bursts (each fires CALLS_PER_CYCLE work units; echoes failed count) ---
burst_invite() {
    sipp -sf sipp/invite_uac_fast.xml "$PROXY" -m "$CALLS_PER_CYCLE" -r "$CPS" -t "$SIPP_T" \
        -i "$UAC_IP" -p "$UAC_PORT" -s bob1 -trace_stat -stf /tmp/leak_uac.csv -fd 1 > /dev/null 2>&1 || true
    while pgrep -f "invite_uac_fast.xml" > /dev/null 2>&1; do sleep 1; done
    [ -f /tmp/leak_uac.csv ] && tail -1 /tmp/leak_uac.csv | awk -F';' '{print $18+0}' || echo 0
}
burst_register() {
    # Auth'd REGISTER churn for bob2 — exercises the REGISTER dispatch +
    # digest auth + registrar.save/refresh path (the original prod symptom).
    # Uses bob2 (NOT the call target bob1) so it doesn't hijack call routing.
    sipp -sf sipp/register.xml "$PROXY" -m "$CALLS_PER_CYCLE" -r "$CPS" -t "$SIPP_T" \
        -i "$UAC_IP" -p "$UAC_PORT" -s bob2 -au bob2 -ap secret \
        -trace_stat -stf /tmp/leak_reg.csv -fd 1 > /dev/null 2>&1 || true
    while pgrep -f "register.xml" > /dev/null 2>&1; do sleep 1; done
    [ -f /tmp/leak_reg.csv ] && tail -1 /tmp/leak_reg.csv | awk -F';' '{print $18+0}' || echo 0
}

echo ""
echo "[*] Warm-up (invite + register), then idle ${IDLE_SECS}s ..."
burst_invite > /dev/null; burst_register > /dev/null
sleep "$IDLE_SECS"
ALLOC_BASE=$(read_gauge memory_allocated_bytes)
PY_BASE=$(read_gauge python_allocated_blocks)
echo "[=] baseline: allocated=$((ALLOC_BASE/1048576)) MB  python_blocks=$PY_BASE  dialog=$(read_gauge proxy_dialog_sessions)"
echo ""

FAILED_TOTAL=0; LEAK=0
for scenario in invite register; do
    echo "--- scenario: $scenario ---"
    for cycle in $(seq 1 "$CYCLES"); do
        f=$("burst_$scenario")
        FAILED_TOTAL=$((FAILED_TOTAL + ${f:-0}))
        sleep "$IDLE_SECS"
        alloc=$(read_gauge memory_allocated_bytes); pyb=$(read_gauge python_allocated_blocks)
        dialog=$(read_gauge proxy_dialog_sessions)
        da=$(( (alloc - ALLOC_BASE) / 1048576 )); dp=$(( pyb - PY_BASE ))
        [ "${dialog:-0}" -ne 0 ] && LEAK=1
        printf "  %-9s cyc %d/%d: allocated=%d MB (Δ%+d)  python_blocks=%s (Δ%+d)  dialog=%s  failed=%s\n" \
            "$scenario" "$cycle" "$CYCLES" "$((alloc/1048576))" "$da" "${pyb:-?}" "$dp" "${dialog:-?}" "${f:-0}"
    done
done

ALLOC_FIN=$(read_gauge memory_allocated_bytes); PY_FIN=$(read_gauge python_allocated_blocks)
DIALOG_FIN=$(read_gauge proxy_dialog_sessions)
ALLOC_GROWTH=$(( (ALLOC_FIN - ALLOC_BASE) / 1048576 )); PY_GROWTH=$(( PY_FIN - PY_BASE ))

echo ""
echo "--- Results ---"
echo "  jemalloc allocated:  $((ALLOC_BASE/1048576)) → $((ALLOC_FIN/1048576)) MB  (Δ ${ALLOC_GROWTH}, budget ${ALLOC_BUDGET_MB})"
echo "  python blocks:       $PY_BASE → $PY_FIN  (Δ ${PY_GROWTH}, budget ${PYBLOCKS_BUDGET})"
echo "  dialog_sessions:     final=$DIALOG_FIN (must be 0)    failed calls: $FAILED_TOTAL"
echo ""

STATUS=0
[ "$FAILED_TOTAL" -ne 0 ] && { echo "=== FAIL: $FAILED_TOTAL failed calls ==="; STATUS=1; }
{ [ "$LEAK" -ne 0 ] || [ "${DIALOG_FIN:-1}" -ne 0 ]; } && { echo "=== FAIL: dialog_sessions did not drain to 0 ==="; STATUS=1; }
[ "$ALLOC_GROWTH" -gt "$ALLOC_BUDGET_MB" ] && { echo "=== FAIL: jemalloc allocated grew ${ALLOC_GROWTH} MB (Rust leak) ==="; STATUS=1; }
[ "$PY_GROWTH" -gt "$PYBLOCKS_BUDGET" ] && { echo "=== FAIL: python blocks grew ${PY_GROWTH} (Python leak) ==="; STATUS=1; }
[ "$STATUS" -eq 0 ] && echo "=== PASS: rust+python allocations flat, dialog drains to 0, 0 failed ==="
exit $STATUS
