set -u

# Maximum-call-duration SIPp test.
#
# Three arms, because the cap can arrive by three different routes and only one
# of them goes through the script:
#
#   dial     call.dial(max_duration=5) — the per-call kwarg.
#   config   b2bua.max_call_duration_secs, with the dial saying nothing. This is
#            the arm that covers every call the dial plan is silent about.
#   optout   the config cap is set AND the call passes max_duration=0, so the
#            call must SURVIVE. Without this arm a cap applied unconditionally
#            would pass the other two.
#
# In the first two arms neither SIPp peer ever sends a BYE, no session timer is
# configured, and the ring timeout stopped applying at the 200 OK — so the BYE
# both legs wait for can only be the duration cap, and each leg asserts it
# carries RFC 3326 Reason: Q.850;cause=102.

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
SIPHON="${SIPHON_BIN:-$ROOT/target/debug/siphon}"
PY="${PYO3_PYTHON:-python3}"
CONFIG="sipp/configs/siphon.max-duration-test.yaml"
CAP_SECS="${MAX_DURATION_SECS:-5}"

run_mode() {
  mode="$1"
  log="$(mktemp -d)"
  echo "=== mode: $mode (logs in $log) ==="

  # The `dial` arm must prove the kwarg works with NO configured ceiling behind
  # it; the other two need the ceiling present.
  if [ "$mode" = "dial" ]; then
    config_cap=0
  else
    config_cap="$CAP_SECS"
  fi

  if [ "$mode" = "optout" ]; then
    uac_scenario="sipp/b2bua_max_duration_optout_uac.xml"
    uas_scenario="sipp/b2bua_session_timer_uas.xml"
    sipp_timeout="30s"
  else
    uac_scenario="sipp/b2bua_max_duration_uac.xml"
    uas_scenario="sipp/b2bua_max_duration_uas.xml"
    sipp_timeout="20s"
  fi

  pids=()
  cleanup() {
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
  }

  MODE="$mode" MAX_DURATION_SECS="$CAP_SECS" MAX_CALL_DURATION_SECS="$config_cap" \
    PYO3_PYTHON="$PY" "$SIPHON" -c "$CONFIG" > "$log/siphon.log" 2>&1 & pids+=($!)
  sleep 3

  sipp -sf "$uas_scenario" -i 127.0.0.1 -p 5072 -m 1 -timeout "$sipp_timeout" -timeout_error \
    -trace_err -error_file "$log/uas.err" -message_file "$log/uas.msg" \
    > "$log/uas.log" 2>&1 & pids+=($!)
  sleep 1

  sipp 127.0.0.1:5060 -sf "$uac_scenario" -i 127.0.0.1 -p 5090 -m 1 \
    -timeout "$sipp_timeout" -timeout_error \
    -trace_err -error_file "$log/uac.err" -message_file "$log/uac.msg" \
    > "$log/uac.log" 2>&1
  uac_rc=$?

  wait "${pids[1]}" 2>/dev/null; uas_rc=$?

  swept=0
  if grep -q "maximum call duration reached" "$log/siphon.log"; then
    swept=1
  fi
  # A framework teardown is not a peer hangup, so @b2bua.on_bye must stay quiet.
  handler_fired=0
  if grep -q "on_bye fired" "$log/siphon.log"; then
    handler_fired=1
  fi

  cleanup
  echo "UAC exit=$uac_rc  UAS exit=$uas_rc  cap-fired=$swept  on_bye=$handler_fired"

  # In the capped arms the cap must fire and @b2bua.on_bye must NOT: a framework
  # teardown is not a peer hangup. In the opt-out arm it is exactly the other way
  # round — the caller hangs up for real, so on_bye firing is itself proof the
  # call was still up when it did.
  if [ "$mode" = "optout" ]; then
    expect_swept=0
    expect_handler=1
  else
    expect_swept=1
    expect_handler=0
  fi

  if [ "$uac_rc" -eq 0 ] && [ "$uas_rc" -eq 0 ] \
     && [ "$swept" -eq "$expect_swept" ] && [ "$handler_fired" -eq "$expect_handler" ]; then
    if [ "$mode" = "optout" ]; then
      echo "PASS ($mode): max_duration=0 survived a ${CAP_SECS}s configured ceiling; the caller's own BYE ended it"
    else
      echo "PASS ($mode): both legs BYEd with Q.850;cause=102 after ${CAP_SECS}s"
    fi
    return 0
  fi
  echo "FAIL ($mode) — siphon log tail:"; tail -40 "$log/siphon.log"
  echo "UAC err:"; cat "$log/uac.err" 2>/dev/null
  echo "UAS err:"; cat "$log/uas.err" 2>/dev/null
  return 1
}

MODE="${MODE:-all}"
rc=0
if [ "$MODE" = "all" ]; then
  run_mode dial || rc=1
  run_mode config || rc=1
  run_mode optout || rc=1
else
  run_mode "$MODE" || rc=1
fi
exit "$rc"
