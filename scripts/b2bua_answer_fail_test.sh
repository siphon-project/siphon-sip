#!/usr/bin/env bash
# Answer-time failure SIPp test (no docker).
#
# Runs siphon (B2BUA) + a callee that ANSWERS + a caller, with an
# @b2bua.on_answer that fails. Asserts that siphon fails the caller (500) and
# releases the answered B-leg (ACK then BYE), rather than forwarding the 2xx and
# connecting a call that has no media path.
#
# Both failure shapes are covered:
#   MODE=raise      (default) the handler raises — the real incident's shape,
#                   a media backend that refused the answer.
#   MODE=terminate  the handler calls call.terminate().
#   MODE=both       run raise then terminate.
#
# Scope: this covers the SIP wire behaviour and that it came from the answer-time
# gate. It does NOT cover the charging half of the same fix (no answer-time Rf
# ACR-START / Ro CCR-UPDATE for a call that is about to fail) — this config has
# no CDF or OCS peer, so those emissions are inert here and an assertion on them
# would pass whatever the code did. Charging against a real CGRateS lives in
# scripts/charging_test.sh.
#
# Requires: sipp on PATH, a built siphon binary (SIPHON_BIN=... or
# target/debug/siphon), python3.
set -u

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
SIPHON="${SIPHON_BIN:-$ROOT/target/debug/siphon}"
PY="${PYO3_PYTHON:-python3}"
CONFIG="sipp/configs/siphon.answer-fail-test.yaml"

run_mode() {
  mode="$1"
  log="$(mktemp -d)"
  echo "=== mode: $mode (logs in $log) ==="

  pids=()
  cleanup() {
    for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
  }

  # 1. siphon B2BUA, with on_answer failing in the selected way.
  MODE="$mode" PYO3_PYTHON="$PY" "$SIPHON" -c "$CONFIG" > "$log/siphon.log" 2>&1 & pids+=($!)
  sleep 3

  # 2. the callee — answers 200, then must receive BOTH the ACK and the BYE.
  #    It exits non-zero if the BYE never comes, which is the regression.
  sipp -sf sipp/b2bua_answer_fail_uas.xml -i 127.0.0.1 -p 5072 -m 1 -timeout 20s -timeout_error \
    -trace_err -error_file "$log/uas.err" -message_file "$log/uas.msg" \
    > "$log/uas.log" 2>&1 & pids+=($!)
  sleep 1

  # 3. the caller — must receive 500, never a 2xx.
  sipp 127.0.0.1:5060 -sf sipp/b2bua_answer_fail_uac.xml -i 127.0.0.1 -p 5090 -m 1 \
    -timeout 20s -timeout_error \
    -trace_err -error_file "$log/uac.err" -message_file "$log/uac.msg" \
    > "$log/uac.log" 2>&1
  uac_rc=$?

  wait "${pids[1]}" 2>/dev/null; uas_rc=$?

  # Prove the 500 came from the answer-time gate and not from something else
  # failing the call earlier (a dial that never connected would also leave the
  # caller with a failure, and would pass the wire assertions above while
  # testing nothing).
  gated=0
  if grep -q "failing a call whose B-leg answered" "$log/siphon.log"; then
    gated=1
  fi

  cleanup
  echo "UAC exit=$uac_rc  UAS exit=$uas_rc  gate-fired=$gated"

  if [ "$uac_rc" -eq 0 ] && [ "$uas_rc" -eq 0 ] && [ "$gated" -eq 1 ]; then
    echo "PASS ($mode): caller got 500 from the answer-time gate, answered B-leg got ACK+BYE"
    return 0
  fi
  echo "FAIL ($mode) — siphon log tail:"; tail -40 "$log/siphon.log"
  echo "UAC err:"; cat "$log/uac.err" 2>/dev/null
  echo "UAS err:"; cat "$log/uas.err" 2>/dev/null
  return 1
}

MODE="${MODE:-raise}"
rc=0
if [ "$MODE" = "both" ]; then
  run_mode raise || rc=1
  run_mode terminate || rc=1
else
  run_mode "$MODE" || rc=1
fi
exit "$rc"
