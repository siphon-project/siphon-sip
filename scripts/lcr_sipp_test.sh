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
# Carrier A's UAS is skipped entirely in `unroutable` mode — the whole point is
# that no INVITE is ever sent to it, so there is nothing for a UAS to receive.
RUN_CARRIER_A_UAS=1
if [ "$MODE" = "timeout" ]; then
  CARRIER_A_SCENARIO="sipp/b2bua_lcr_carrier_a_silent_uas.xml"
  export LCR_CARRIER_A_TIMEOUT=3
  echo "mode: timeout (carrier A silent, ring timeout 3s)"
elif [ "$MODE" = "unroutable" ]; then
  # Carrier A's next-hop does not resolve. siphon knows that the instant it
  # tries, so the sequence must advance to carrier B immediately instead of
  # arming carrier A's ring timeout and charging it a 408 for a call it never
  # saw. The 20 s timeout is the assertion: if the advance waits for it, the
  # elapsed check below fails.
  CARRIER_A_SCENARIO=""
  RUN_CARRIER_A_UAS=0
  export LCR_CARRIER_A="sip:carrier-a.invalid:5071"
  export LCR_CARRIER_A_TIMEOUT=20
  echo "mode: unroutable (carrier A next-hop does not resolve, ring timeout 20s)"
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
carriera_pid=""
if [ "$RUN_CARRIER_A_UAS" = "1" ]; then
  sipp -sf "$CARRIER_A_SCENARIO" -i 127.0.0.1 -p 5071 -m 1 -timeout 25s -timeout_error \
    -trace_err -error_file "$LOG/carrierA.err" -message_file "$LOG/carrierA.msg" \
    > "$LOG/carrierA.log" 2>&1 & carriera_pid=$!; pids+=($carriera_pid)
fi

# 4. carrier B UAS — answers 200
sipp -sf sipp/b2bua_lcr_carrier_b_uas.xml -i 127.0.0.1 -p 5072 -m 1 -timeout 20s -timeout_error \
  -trace_err -error_file "$LOG/carrierB.err" -message_file "$LOG/carrierB.msg" \
  > "$LOG/carrierB.log" 2>&1 & carrierb_pid=$!; pids+=($carrierb_pid)
sleep 1

# 5. UAC — expects a single 200 (failover is transparent)
call_start=$(date +%s)
sipp 127.0.0.1:5060 -sf sipp/b2bua_lcr_uac.xml -i 127.0.0.1 -p 5090 -m 1 -timeout 30s -timeout_error \
  -trace_err -error_file "$LOG/uac.err" -message_file "$LOG/uac.msg" \
  > "$LOG/uac.log" 2>&1
uac_rc=$?
call_secs=$(( $(date +%s) - call_start ))

# Assert BOTH carriers completed their scenarios — this is the failover proof:
#   - carrier A (pids[2]) exits 0 only if it received the INVITE AND ACKed its
#     503, i.e. siphon actually TRIED carrier A first (not just carrier B).
#   - carrier B (pids[3]) exits 0 only if it answered AND received the BYE.
# Without checking carrier A, a "caller got 200" could hide a skipped-failover bug.
# In `unroutable` mode carrier A has no UAS at all — not being contacted IS the
# expected behaviour there — so it is scored as passed.
if [ -n "$carriera_pid" ]; then
  wait "$carriera_pid" 2>/dev/null; carriera_rc=$?
else
  carriera_rc=0
fi
wait "$carrierb_pid" 2>/dev/null; carrierb_rc=$?

# Flush the pcap (SIGTERM makes hep_to_pcap.py write it), after giving siphon a
# moment to HEP-trace the last messages.
if [ -n "$HEP_PID" ]; then
  sleep 1
  kill -TERM "$HEP_PID" 2>/dev/null
  wait "$HEP_PID" 2>/dev/null
  echo "pcap written: $PCAP_OUT"
fi

# b2bua.log_dial is on in the test config: every carrier siphon actually dialled
# must have left an info line naming it. Two carriers are dialled in reject /
# timeout mode; in unroutable mode carrier A is never dialled, so exactly one.
dialled=$(grep -c "B2BUA: dialling B-leg" "$LOG/siphon.log")
expect_dialled=2
extra_ok=1
extra_note=""

if [ "$MODE" = "unroutable" ]; then
  expect_dialled=1
  # The defect this mode exists for: siphon knows carrier A is unroutable the
  # instant it tries, but used to arm carrier A's ring timeout anyway and only
  # advance when it fired. Carrier A's timeout is 20 s, so anything near it
  # means the failover is waiting on a timer rather than on the known failure.
  if [ "$call_secs" -ge 10 ]; then
    extra_ok=0
    extra_note="FAIL: took ${call_secs}s — the sequence waited for carrier A's ring timeout instead of advancing on the send failure"
  fi
  # ...and the burned carrier must be recorded as never dialled, so nothing
  # downstream (route_attempts / lcr_attempts / on_route_failure) reads a local
  # routing failure as something the carrier answered.
  if ! grep -q "burned carrier-a 503 .* dialed=False" "$LOG/siphon.log"; then
    extra_ok=0
    extra_note="$extra_note
FAIL: carrier-a was not recorded on route_attempts as dialed=False"
  fi
  if ! grep -q "carrier burned without dialling" "$LOG/siphon.log"; then
    extra_ok=0
    extra_note="$extra_note
FAIL: no info line reporting the undialled carrier"
  fi
fi

echo "UAC exit=$uac_rc  carrierA exit=$carriera_rc  carrierB exit=$carrierb_rc  dial lines=$dialled  call=${call_secs}s"
if [ "$uac_rc" -eq 0 ] && [ "$carriera_rc" -eq 0 ] && [ "$carrierb_rc" -eq 0 ] \
   && [ "$dialled" -eq "$expect_dialled" ] && [ "$extra_ok" -eq 1 ]; then
  if [ "$MODE" = "unroutable" ]; then
    echo "PASS: carrier A was unroutable, siphon advanced to carrier B at once (${call_secs}s, not its 20s ring timeout)"
    echo "      carrier A recorded on route_attempts as dialed=False — never blamed for a call it did not see"
  else
    echo "PASS: carrier A rejected 503, siphon failed over to carrier B (200); caller saw one 200"
    echo "      both carrier attempts reported at info (b2bua.log_dial)"
  fi
  exit 0
fi
if [ "$dialled" -ne "$expect_dialled" ]; then
  echo "FAIL: expected $expect_dialled 'B2BUA: dialling B-leg' info lines, got $dialled"
fi
[ -n "$extra_note" ] && echo "$extra_note"
echo "FAIL — siphon log tail:"; tail -30 "$LOG/siphon.log"
echo "UAC err:"; cat "$LOG/uac.err" 2>/dev/null
exit 1
