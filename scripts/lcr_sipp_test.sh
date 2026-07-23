#!/usr/bin/env bash
# Local LCR sequential-failover SIPp test (no docker).
#
# Runs a mock LCR API + siphon (B2BUA, LCR) + carrier-A UAS (rejects 503) +
# carrier-B UAS (answers 200) + a UAC, and asserts the caller receives a 200 —
# i.e. siphon failed over from carrier A to carrier B transparently, on a fresh
# B-leg dialog per carrier.
#
# Requires: sipp on PATH, a built siphon binary (SIPHON_BIN=... or
# target/debug/siphon), python3.
set -u

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
SIPHON="${SIPHON_BIN:-$ROOT/target/debug/siphon}"
PY="${PYO3_PYTHON:-python3}"
LOG="$(mktemp -d)"
echo "logs in $LOG"

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

# MODE=reject (default): carrier A returns 503 (a reroute cause).
# MODE=timeout: carrier A is SILENT; siphon rings it for the route's timeout_secs
#   then CANCELs and re-routes ("try carrier X for N seconds, then re-route").
MODE="${MODE:-reject}"
if [ "$MODE" = "timeout" ]; then
  CARRIER_A_SCENARIO="sipp/b2bua_lcr_carrier_a_silent_uas.xml"
  export LCR_CARRIER_A_TIMEOUT=3
  echo "mode: timeout (carrier A silent, ring timeout 3s)"
else
  CARRIER_A_SCENARIO="sipp/b2bua_lcr_carrier_a_uas.xml"
  echo "mode: reject (carrier A 503)"
fi

# PCAP=1: capture a real pcap of the whole failover via siphon's HEP feed
# (hep_to_pcap.py). Must start the HEP receiver BEFORE siphon.
CONFIG="sipp/configs/siphon.lcr-test.yaml"
HEP_PID=""
if [ "${PCAP:-0}" = "1" ]; then
  CONFIG="sipp/configs/siphon.lcr-test-hep.yaml"
  PCAP_OUT="${PCAP_OUT:-$LOG/lcr_failover_${MODE}.pcap}"
  LCR_PCAP_OUT="$PCAP_OUT" "$PY" scripts/hep_to_pcap.py 2>"$LOG/hep.log" & HEP_PID=$!
  sleep 0.5
  echo "pcap capture on (HEP) -> $PCAP_OUT"
fi

# 1. mock LCR API (returns carrier-a then carrier-b by next-hop)
"$PY" scripts/lcr_mock_api.py & pids+=($!)

# 2. siphon B2BUA with LCR
PYO3_PYTHON="$PY" "$SIPHON" -c "$CONFIG" > "$LOG/siphon.log" 2>&1 & pids+=($!)
sleep 3

# 3. carrier A UAS — rejects 503 (reject mode) or stays silent (timeout mode)
sipp -sf "$CARRIER_A_SCENARIO" -i 127.0.0.1 -p 5071 -m 1 -timeout 25s -timeout_error \
  -trace_err -error_file "$LOG/carrierA.err" -message_file "$LOG/carrierA.msg" \
  > "$LOG/carrierA.log" 2>&1 & pids+=($!)

# 4. carrier B UAS — answers 200
sipp -sf sipp/b2bua_lcr_carrier_b_uas.xml -i 127.0.0.1 -p 5072 -m 1 -timeout 20s -timeout_error \
  -trace_err -error_file "$LOG/carrierB.err" -message_file "$LOG/carrierB.msg" \
  > "$LOG/carrierB.log" 2>&1 & pids+=($!)
sleep 1

# 5. UAC — expects a single 200 (failover is transparent)
sipp 127.0.0.1:5060 -sf sipp/b2bua_lcr_uac.xml -i 127.0.0.1 -p 5090 -m 1 -timeout 20s -timeout_error \
  -trace_err -error_file "$LOG/uac.err" -message_file "$LOG/uac.msg" \
  > "$LOG/uac.log" 2>&1
uac_rc=$?

# Assert BOTH carriers completed their scenarios — this is the failover proof:
#   - carrier A (pids[2]) exits 0 only if it received the INVITE AND ACKed its
#     503, i.e. siphon actually TRIED carrier A first (not just carrier B).
#   - carrier B (pids[3]) exits 0 only if it answered AND received the BYE.
# Without checking carrier A, a "caller got 200" could hide a skipped-failover bug.
wait "${pids[2]}" 2>/dev/null; carriera_rc=$?
wait "${pids[3]}" 2>/dev/null; carrierb_rc=$?

# Flush the pcap (SIGTERM makes hep_to_pcap.py write it), after giving siphon a
# moment to HEP-trace the last messages.
if [ -n "$HEP_PID" ]; then
  sleep 1
  kill -TERM "$HEP_PID" 2>/dev/null
  wait "$HEP_PID" 2>/dev/null
  echo "pcap written: $PCAP_OUT"
fi

echo "UAC exit=$uac_rc  carrierA exit=$carriera_rc  carrierB exit=$carrierb_rc"
if [ "$uac_rc" -eq 0 ] && [ "$carriera_rc" -eq 0 ] && [ "$carrierb_rc" -eq 0 ]; then
  echo "PASS: carrier A rejected 503, siphon failed over to carrier B (200); caller saw one 200"
  exit 0
fi
echo "FAIL — siphon log tail:"; tail -30 "$LOG/siphon.log"
echo "UAC err:"; cat "$LOG/uac.err" 2>/dev/null
exit 1
