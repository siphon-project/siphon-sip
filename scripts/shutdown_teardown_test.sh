set -u

# Shutdown-teardown SIPp test — the acceptance criterion for what a drain
# deadline does to the calls it is still holding.
#
# A call lasts minutes and `drain_secs` is seconds, so the deadline is the
# normal path on any restart taken with traffic up, not the exceptional one.
# Before the teardown pass, that path ended at
#   "drain timeout — exiting with in-flight work still active"
# and put nothing on the wire: no BYE on either leg, no charging stop, no media
# release, no CDR. The far side kept its channel until someone hung it up.
#
# Nothing else in this config can end the call — neither SIPp peer sends a BYE,
# no session timer, no duration cap, and the ring timeout stopped applying at
# the 200 OK — so the BYE both legs wait for can only be the shutdown pass, and
# each asserts it carries RFC 3326 Reason: Q.850;cause=16 (normal clearing),
# which is what separates it from a timeout teardown's cause=102.
#
# Two arms:
#   teardown   teardown_secs=5 — both legs get their BYE before siphon exits.
#   disabled   teardown_secs=0 — the pre-1.9.2 behaviour, exactly: siphon exits
#              at the deadline and neither leg hears anything. Without this arm
#              a teardown that ran unconditionally would pass the first one and
#              nobody would notice the knob did nothing.

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
SIPHON="${SIPHON_BIN:-$ROOT/target/debug/siphon}"
PY="${PYO3_PYTHON:-python3}"
CONFIG="sipp/configs/siphon.shutdown-test.yaml"

run_mode() {
  mode="$1"
  log="$(mktemp -d)"
  echo "=== mode: $mode (logs in $log) ==="

  if [ "$mode" = "disabled" ]; then
    teardown_secs=0
    # Nothing will come, so do not sit through a long SIPp timeout for it.
    sipp_timeout="12s"
  else
    teardown_secs=5
    sipp_timeout="25s"
  fi

  pids=()
  cleanup() {
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
  }

  DRAIN_SECS=1 TEARDOWN_SECS="$teardown_secs" PYO3_PYTHON="$PY" \
    "$SIPHON" -c "$CONFIG" > "$log/siphon.log" 2>&1 & siphon_pid=$!
  pids+=("$siphon_pid")
  sleep 3

  sipp -sf sipp/b2bua_shutdown_uas.xml -i 127.0.0.1 -p 5072 -m 1 \
    -timeout "$sipp_timeout" -timeout_error \
    -trace_err -error_file "$log/uas.err" -message_file "$log/uas.msg" \
    > "$log/uas.log" 2>&1 & uas_pid=$!
  pids+=("$uas_pid")
  sleep 1

  # The UAC runs in the background too: the signal has to arrive while it is
  # sitting on an answered call, which is the whole point.
  sipp 127.0.0.1:5060 -sf sipp/b2bua_shutdown_uac.xml -i 127.0.0.1 -p 5090 -m 1 \
    -timeout "$sipp_timeout" -timeout_error \
    -trace_err -error_file "$log/uac.err" -message_file "$log/uac.msg" \
    > "$log/uac.log" 2>&1 & uac_pid=$!
  pids+=("$uac_pid")

  # Wait for the call to be up before signalling. Polling the log rather than
  # sleeping a guess: a signal that lands before the 200 OK would test the
  # ringing path, which is a different arm of the pass.
  answered=0
  for _ in $(seq 1 40); do
    if grep -q "shutdown-test call answered" "$log/siphon.log" 2>/dev/null; then
      answered=1
      break
    fi
    sleep 0.25
  done
  if [ "$answered" -eq 0 ]; then
    echo "FAIL ($mode): the call never answered — siphon log tail:"; tail -40 "$log/siphon.log"
    cleanup
    return 1
  fi
  sleep 1

  kill -TERM "$siphon_pid" 2>/dev/null

  wait "$uac_pid" 2>/dev/null; uac_rc=$?
  wait "$uas_pid" 2>/dev/null; uas_rc=$?
  wait "$siphon_pid" 2>/dev/null

  # A framework teardown is not a peer hangup, so @b2bua.on_bye must stay quiet.
  handler_fired=0
  if grep -q "on_bye fired" "$log/siphon.log"; then
    handler_fired=1
  fi
  torn_down=0
  if grep -q "shutdown teardown complete" "$log/siphon.log"; then
    torn_down=1
  fi

  cleanup
  echo "UAC exit=$uac_rc  UAS exit=$uas_rc  teardown-ran=$torn_down  on_bye=$handler_fired"

  if [ "$mode" = "disabled" ]; then
    # Both peers must TIME OUT: no BYE reached either of them. A zero exit here
    # would mean the knob did nothing.
    if [ "$uac_rc" -ne 0 ] && [ "$uas_rc" -ne 0 ] && [ "$torn_down" -eq 0 ]; then
      echo "PASS (disabled): teardown_secs=0 left both legs alone, as it did before 1.9.2"
      return 0
    fi
  else
    if [ "$uac_rc" -eq 0 ] && [ "$uas_rc" -eq 0 ] \
       && [ "$torn_down" -eq 1 ] && [ "$handler_fired" -eq 0 ]; then
      echo "PASS (teardown): both legs BYEd with Q.850;cause=16 before siphon exited"
      return 0
    fi
  fi

  echo "FAIL ($mode) — siphon log tail:"; tail -40 "$log/siphon.log"
  echo "UAC err:"; cat "$log/uac.err" 2>/dev/null
  echo "UAS err:"; cat "$log/uas.err" 2>/dev/null
  return 1
}

MODE="${MODE:-all}"
rc=0
if [ "$MODE" = "all" ]; then
  run_mode teardown || rc=1
  run_mode disabled || rc=1
else
  run_mode "$MODE" || rc=1
fi
exit $rc
