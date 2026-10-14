#!/usr/bin/env bash
# @b2bua.on_reoffer SIPp test (no docker).
#
# Runs siphon (B2BUA) + a callee + a caller. The caller holds (re-INVITE,
# sendonly), which the script answers itself: the caller must get a 200 with
# a=recvonly and the callee nothing. The caller then resumes, which the script
# relays: the callee must get it, marked X-Reoffer: resume. Both hooks must
# have run, which the siphon log shows.
#
# Requires: sipp on PATH, a built siphon binary (SIPHON_BIN=... or
# target/debug/siphon), python3.
set -u

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"
SIPHON="${SIPHON_BIN:-$ROOT/target/debug/siphon}"
PY="${PYO3_PYTHON:-python3}"
PORT="${SIPHON_PORT:-5060}"
log="$(mktemp -d)"
echo "logs in $log"
# The checked-in config, on PORT when 5060 is taken on this host.
CONFIG="$log/siphon.yaml"
sed "s/127.0.0.1:5060/127.0.0.1:$PORT/" sipp/configs/siphon.reoffer-test.yaml > "$CONFIG"

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
}
trap cleanup EXIT

PYO3_PYTHON="$PY" "$SIPHON" -c "$CONFIG" > "$log/siphon.log" 2>&1 & pids+=($!)
sleep 3

sipp -sf sipp/b2bua_reoffer_uas.xml -i 127.0.0.1 -p 5074 -m 1 -timeout 30s -timeout_error \
  -trace_err -error_file "$log/uas.err" -message_file "$log/uas.msg" -trace_msg \
  > "$log/uas.log" 2>&1 & pids+=($!)
uas_pid=$!
sleep 1

sipp "127.0.0.1:$PORT" -sf sipp/b2bua_reoffer_uac.xml -i 127.0.0.1 -p 5092 -m 1 \
  -timeout 30s -timeout_error \
  -trace_err -error_file "$log/uac.err" -message_file "$log/uac.msg" -trace_msg \
  > "$log/uac.log" 2>&1
uac_rc=$?
wait "$uas_pid" 2>/dev/null; uas_rc=$?

expect() {
  if grep -q "$1" "$log/siphon.log"; then
    return 0
  fi
  echo "missing from the siphon log: $1"
  return 1
}
logged=0
expect "reoffer seen: INVITE a hold" || logged=1
expect "reoffer answered: hold 200 recvonly True" || logged=1
expect "reoffer seen: INVITE a resume" || logged=1
expect "reoffer answered: resume 200 sendrecv False" || logged=1

echo "UAC exit=$uac_rc  UAS exit=$uas_rc  hooks-logged=$((1 - logged))"
if [ "$uac_rc" -eq 0 ] && [ "$uas_rc" -eq 0 ] && [ "$logged" -eq 0 ]; then
  echo "PASS: the hold was answered by the script and the resume relayed"
  exit 0
fi
echo "FAIL. siphon log tail:"; tail -60 "$log/siphon.log"
echo "UAC err:"; cat "$log/uac.err" 2>/dev/null
echo "UAS err:"; cat "$log/uas.err" 2>/dev/null
exit 1
