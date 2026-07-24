#!/usr/bin/env bash
#
# SIPhon INVITE scale test
#
# Usage:
#   ./scripts/scale_test.sh [total_calls] [cps] [num_uacs]
#
# Examples:
#   ./scripts/scale_test.sh 10000 1000 1     # 10k calls, 1k cps, 1 SIPp
#   ./scripts/scale_test.sh 100000 20000 4   # 100k calls, 20k cps, 4 SIPps
#
# Prerequisites:
#   - sipp installed
#   - siphon.yaml with bob/secret in auth.users
#
# The release binary is rebuilt automatically (cargo is a no-op if fresh)
# to avoid running stale code against a modified tree.

set -euo pipefail

TOTAL=${1:-10000}
CPS=${2:-1000}
NUM_UACS=${3:-1}

CALLS_PER_UAC=$((TOTAL / NUM_UACS))
CPS_PER_UAC=$((CPS / NUM_UACS))
PROXY="127.0.0.1:5060"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$NUM_UACS" -gt 32 ]; then
    echo "FAIL: NUM_UACS > 32 not supported (siphon.yaml registers bob1..bob32)"
    exit 1
fi

cd "$SCRIPT_DIR"

cleanup() {
    pkill -f "invite_uac" 2>/dev/null || true
    pkill -f "invite_uas" 2>/dev/null || true
    # SIGKILL siphon — perf runs are independent, the graceful drain
    # (server.drain_secs default 30) would otherwise keep the listener
    # bound for half a minute between rows and block port :5060.
    pkill -9 -f "target/release/siphon" 2>/dev/null || true
}
trap cleanup EXIT

# --- Pick Python interpreter ---
# CLAUDE.md baseline assumes free-threaded Python 3.14t. Without it we'd be
# benchmarking a GIL-serialized build, which silently ceiling-limits throughput
# regardless of how many cores the box has. Resolution order:
#   1. PYO3_PYTHON env var if explicitly set
#   2. uv-installed free-threaded build (cpython-3.14*+freethreaded)
#   3. system `python3` (fallback — likely GIL build, prints a warning)
if [ -z "${PYO3_PYTHON:-}" ]; then
    UV_FT_BIN=""
    if command -v uv > /dev/null 2>&1; then
        UV_FT_BIN="$(uv python find 3.14 --no-managed-python 2>/dev/null || true)"
        if [ -z "$UV_FT_BIN" ] || ! "$UV_FT_BIN" -c "import sysconfig,sys; sys.exit(0 if sysconfig.get_config_var('Py_GIL_DISABLED') else 1)" 2>/dev/null; then
            UV_FT_BIN="$(uv python list --only-installed 2>/dev/null | awk '/freethreaded/ && /-linux-/ {for (i=1;i<=NF;i++) if ($i ~ /\/python3\.14t$/) {print $i; exit}}' || true)"
        fi
    fi
    if [ -z "$UV_FT_BIN" ]; then
        # Glob fallback: typical uv install path
        for cand in "$HOME/.local/share/uv/python/cpython-3.14"*"+freethreaded"*"/bin/python3.14t"; do
            [ -x "$cand" ] && { UV_FT_BIN="$cand"; break; }
        done
    fi
    if [ -n "$UV_FT_BIN" ] && [ -x "$UV_FT_BIN" ]; then
        export PYO3_PYTHON="$UV_FT_BIN"
        echo "[*] Using free-threaded Python: $PYO3_PYTHON"
    else
        export PYO3_PYTHON="python3"
        echo "[!] WARN: free-threaded Python not found — falling back to system python3."
        echo "[!]       Throughput results will be GIL-limited and won't match the README baseline."
        echo "[!]       Install via: uv python install 3.14+freethreaded"
    fi
fi

# If PYO3_PYTHON points at a custom (non-system) Python, the matching libpython
# may not be on the default loader search path — derive its lib/ dir and add it
# to LD_LIBRARY_PATH so the siphon binary can dlopen libpythonX.Y(t).so.
if [ -x "$PYO3_PYTHON" ] && [ -f "$PYO3_PYTHON" ]; then
    # Resolve symlinks (uv installs a `~/.local/bin/python3.14t` shim that
    # points at the real interpreter under `~/.local/share/uv/python/...`).
    PYO3_PYTHON_REAL="$(readlink -f "$PYO3_PYTHON")"
    PY_LIB_DIR="$(dirname "$(dirname "$PYO3_PYTHON_REAL")")/lib"
    if [ -d "$PY_LIB_DIR" ]; then
        case ":${LD_LIBRARY_PATH:-}:" in
            *":$PY_LIB_DIR:"*) ;;
            *) export LD_LIBRARY_PATH="${PY_LIB_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
        esac
    fi
fi

echo "=== SIPhon Scale Test ==="
echo "  Total calls:  $TOTAL"
echo "  Target rate:  $CPS cps"
echo "  UAC instances: $NUM_UACS ($CALLS_PER_UAC calls @ $CPS_PER_UAC cps each)"
echo ""

# --- Build siphon release binary (no-op if already fresh) ---
echo "[*] Building siphon (release)..."
if ! cargo build --release --quiet > /tmp/siphon_scale_build.log 2>&1; then
    echo "FAIL: cargo build failed"
    tail -40 /tmp/siphon_scale_build.log
    exit 1
fi
echo "[+] build ok"

# --- Pick config: MODE=proxy (default) or MODE=b2bua ---
# B2BUA mode rewrites the Python script path in a temp config copy so the
# proxy_default.py routing logic is replaced by b2bua_default.py.
# (siphon.yaml pins advertised_address: 127.0.0.1 for loopback testing — the
# reason the loopback SIPp peers can reach siphon's Via/Contact.)
MODE="${MODE:-proxy}"
case "$MODE" in
    proxy)
        CONFIG_FILE="siphon.yaml"
        echo "[*] Mode: proxy"
        ;;
    b2bua)
        CONFIG_FILE="/tmp/siphon_scale_b2bua.yaml"
        sed 's|scripts/proxy_default.py|scripts/b2bua_default.py|' siphon.yaml > "$CONFIG_FILE"
        echo "[*] Mode: b2bua  (config: $CONFIG_FILE)"
        ;;
    *)
        echo "FAIL: unknown MODE='$MODE' (use 'proxy' or 'b2bua')"
        exit 1
        ;;
esac

# --- Start SIPhon ---
cleanup
sleep 1

RUST_LOG="${RUST_LOG:-warn}" PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
    LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
    ./target/release/siphon -c "$CONFIG_FILE" > /tmp/siphon_scale_proxy.log 2>&1 &
SIPHON_PID=$!
sleep 2

if ! kill -0 $SIPHON_PID 2>/dev/null; then
    echo "FAIL: siphon did not start"
    cat /tmp/siphon_scale_proxy.log
    exit 1
fi
echo "[+] siphon started (PID $SIPHON_PID)"

# --- Register one bob{i} per UAS so the proxy load fans out across N UASes ---
# Each UAS binds to a distinct loopback IP (127.0.0.{1+i}) on port 5060.
# Without distinct IPs, sipp's [local_ip] resolves to the host's hostname
# address (often 127.0.1.1 on Debian/Ubuntu), which differs from where the
# proxy receives — leading to weird Contact-header routing inconsistencies
# and lost in-dialog requests.
UAS_PORT=5061
UAC_PORT=5062

# --- Pick transport: TRANSPORT=udp (default) | tcp ---
# SIPp -t flag: u1=UDP single-socket, t1=TCP one socket per call,
# tn=TCP one socket per call (new connection per call, more like real-world UAC).
# Use t1 for TCP throughput so SIPp keeps a single TCP connection to the proxy.
TRANSPORT="${TRANSPORT:-udp}"
case "$TRANSPORT" in
    udp) SIPP_T="u1"; TPORT_LABEL="UDP" ;;
    tcp) SIPP_T="t1"; TPORT_LABEL="TCP" ;;
    *)
        echo "FAIL: unknown TRANSPORT='$TRANSPORT' (use 'udp' or 'tcp')"
        exit 1
        ;;
esac
echo "[*] Transport: $TPORT_LABEL"

echo "[*] Registering bob1..bob${NUM_UACS} (one UAS per UAC, distinct IPs)..."
REG_FAILED=0
for i in $(seq 1 "$NUM_UACS"); do
    ip="127.0.0.$((1 + i))"
    user="bob${i}"
    log="/tmp/siphon_scale_register_${i}.log"
    sipp -sf sipp/register.xml "$PROXY" -m 1 -t "$SIPP_T" -i "$ip" -p "$UAS_PORT" \
        -s "$user" -au "$user" -ap secret > "$log" 2>&1 || true
    if ! grep -q "Successful call.*1" "$log"; then
        echo "FAIL: registration of $user from $ip failed"
        cat "$log"
        REG_FAILED=1
    fi
done
[ "$REG_FAILED" -eq 0 ] || exit 1
echo "[+] $NUM_UACS bobs registered (127.0.0.2..127.0.0.$((1 + NUM_UACS)))"

# --- Start one UAS per UAC, each on its own loopback IP ---
for i in $(seq 1 "$NUM_UACS"); do
    ip="127.0.0.$((1 + i))"
    sipp -sf sipp/invite_uas_fast.xml -t "$SIPP_T" -i "$ip" -p "$UAS_PORT" -bg > /dev/null 2>&1 || true
done
sleep 1
echo "[+] $NUM_UACS UAS processes started"

# --- Launch UACs ---
# Each UAC also binds to a distinct loopback IP so its [local_ip] in
# Via/Contact is unambiguous. UACs use 127.0.0.{50+i}.
# -fd 1 = 1-second snapshot resolution so we can see peak rate, not avg.
echo ""
echo "--- Running $TOTAL calls at $CPS cps target ---"
START_NS=$(date +%s%N)

for i in $(seq 1 "$NUM_UACS"); do
    ip="127.0.0.$((50 + i))"
    user="bob${i}"
    sipp -sf sipp/invite_uac_fast.xml "$PROXY" \
        -m "$CALLS_PER_UAC" -r "$CPS_PER_UAC" -t "$SIPP_T" \
        -i "$ip" -p "$UAC_PORT" -s "$user" \
        -trace_stat -stf "/tmp/sipp_uac_${i}.csv" -fd 1 \
        -trace_msg -message_file "/tmp/sipp_uac_${i}.msg.log" \
        -bg > /dev/null 2>&1 || true
done

echo "[+] $NUM_UACS UAC(s) launched, waiting..."

# --- Sample siphon CPU% + memory during the run via pidstat ---
# `-u` = CPU, `-r` = memory (RSS in KiB, VSZ in KiB, %MEM).
# `-h` puts everything on one line per sample so awk can parse it.
# 1-second samples → we keep peak CPU% and peak RSS observed during the test.
# 100 % CPU = one fully-saturated logical core.
PIDSTAT_LOG="/tmp/siphon_scale_pidstat.log"
> "$PIDSTAT_LOG"
pidstat -u -r -h -p "$SIPHON_PID" 1 > "$PIDSTAT_LOG" 2>/dev/null &
PIDSTAT_PID=$!

# Poll until all UAC processes finish
while pgrep -f "invite_uac_fast.xml" > /dev/null 2>&1; do
    sleep 1
done

kill "$PIDSTAT_PID" 2>/dev/null || true
wait "$PIDSTAT_PID" 2>/dev/null || true

END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

# pidstat -u -r -h column layout (`-h` puts all stats on one row):
# # Time UID PID %usr %system %guest %wait %CPU CPU minflt/s majflt/s VSZ RSS %MEM Command
# Indices:           1   2   3    4      5      6     7    8    9     10        11   12  13   14   15
# Note: pidstat uses locale decimal — comma in some locales — but %CPU and RSS
# are integers/are tolerant to "$8+0".
PEAK_CPU=$(awk '/^[ \t]*[0-9]/ {if ($8+0 > p) p=$8+0} END {printf "%.0f", p+0}' "$PIDSTAT_LOG")
PEAK_RSS_KB=$(awk '/^[ \t]*[0-9]/ {if ($13+0 > p) p=$13+0} END {printf "%.0f", p+0}' "$PIDSTAT_LOG")
PEAK_RSS_MB=$(awk -v kb="$PEAK_RSS_KB" 'BEGIN {printf "%.1f", kb / 1024}' | tr ',' '.')

# --- Collect results from SIPp stat files ---
# Column reference (sipp -h stat):
#   5  ElapsedTime(C)
#   8  CallRate(C)        — cumulative average call rate
#  16  SuccessfulCall(C)
#  18  FailedCall(C)
#  58  Retransmissions(C)
#  70  ResponseTime1(C)   — INVITE→200 OK ms (mean)
echo ""
echo "--- Results ---"

TOTAL_SUCCESS=0
TOTAL_FAILED=0
TOTAL_RETRANS=0
PEAK_CPS=0
RT_SUM=0
RT_COUNT=0

for i in $(seq 1 "$NUM_UACS"); do
    csv="/tmp/sipp_uac_${i}.csv"
    if [ -f "$csv" ]; then
        last=$(tail -1 "$csv")
        s=$(echo "$last" | awk -F';' '{print $16+0}')
        f=$(echo "$last" | awk -F';' '{print $18+0}')
        rt=$(echo "$last" | awk -F';' '{print $70+0}')
        retrans=$(echo "$last" | awk -F';' '{print $58+0}')
        # Peak periodic CallRate(P) = column 7
        peak=$(awk -F';' 'NR>1 {if ($7+0 > p) p=$7+0} END {print p+0}' "$csv")
        TOTAL_SUCCESS=$((TOTAL_SUCCESS + s))
        TOTAL_FAILED=$((TOTAL_FAILED + f))
        TOTAL_RETRANS=$((TOTAL_RETRANS + retrans))
        if [ "$peak" -gt "$PEAK_CPS" ]; then PEAK_CPS=$peak; fi
        RT_SUM=$(awk "BEGIN {print $RT_SUM + $rt}")
        RT_COUNT=$((RT_COUNT + 1))
        printf "  UAC %d: success=%d failed=%d peak=%d cps  invite_rt=%dms  retrans=%d\n" \
            "$i" "$s" "$f" "$peak" "$rt" "$retrans"
        # Keep CSV for post-mortem analysis
        mv "$csv" "/tmp/sipp_uac_${i}.last.csv"
    else
        echo "  UAC $i: no stats file"
    fi
done

# Aggregate peak across all UACs (sum, since they ran in parallel)
AGG_PEAK_CPS=$(awk "BEGIN {printf \"%d\", $PEAK_CPS * $NUM_UACS}")
# Mean response time across UACs
MEAN_RT=0
if [ "$RT_COUNT" -gt 0 ]; then
    MEAN_RT=$(awk "BEGIN {printf \"%.0f\", $RT_SUM / $RT_COUNT}")
fi
# Wall-clock throughput including ramp+drain (apples-to-apples for sustained load)
WALL_CPS=0
if [ "$ELAPSED_MS" -gt 0 ]; then
    WALL_CPS=$(( (TOTAL_SUCCESS + TOTAL_FAILED) * 1000 / ELAPSED_MS ))
fi

# Check siphon errors
SIPHON_ERRORS=$(grep -aci "error" /tmp/siphon_scale_proxy.log 2>/dev/null || echo 0)

echo ""
echo "  Successful:        $TOTAL_SUCCESS / $TOTAL"
echo "  Failed:            $TOTAL_FAILED"
echo "  Retransmissions:   $TOTAL_RETRANS"
echo "  Wall elapsed:      ${ELAPSED_MS}ms"
echo "  Peak CPS (1s):     ~${AGG_PEAK_CPS}  (per-UAC peak: ${PEAK_CPS})"
echo "  Wall avg CPS:      ~${WALL_CPS}  (includes ramp+drain)"
echo "  Mean INVITE→200:   ${MEAN_RT}ms"
echo "  Peak siphon CPU:   ${PEAK_CPU}%  (100% = 1 logical core)"
echo "  Peak siphon RSS:   ${PEAK_RSS_MB} MB  (${PEAK_RSS_KB} KiB)"
echo "  Proxy errors:      $SIPHON_ERRORS"

echo ""
if [ "$TOTAL_FAILED" -eq 0 ] && [ "$TOTAL_SUCCESS" -ge "$TOTAL" ]; then
    echo "=== PASS: $TOTAL_SUCCESS/$TOTAL  peak ${AGG_PEAK_CPS} cps  cpu ${PEAK_CPU}%  rss ${PEAK_RSS_MB}MB  rt ${MEAN_RT}ms ==="
    exit 0
else
    echo "=== RESULT: $TOTAL_SUCCESS/$TOTAL ($TOTAL_FAILED failed)  peak ${AGG_PEAK_CPS} cps  cpu ${PEAK_CPU}%  rss ${PEAK_RSS_MB}MB  rt ${MEAN_RT}ms ==="
    [ "$TOTAL_FAILED" -eq 0 ] && exit 0 || exit 1
fi
