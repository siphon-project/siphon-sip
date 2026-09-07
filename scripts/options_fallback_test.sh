#!/usr/bin/env bash
# options_fallback_test.sh — no-script-handler fallback regression (real binary).
#
# A script with method-filtered handlers claims nothing for OPTIONS, which is
# the shape every registered deployment ends up in: a registrar qualifies its
# bindings forever, and siphon used to answer each probe `500 Server Internal
# Error`. Nobody noticed, because a qualifying registrar accepts any final
# response as proof of life — the contact showed reachable with a healthy RTT
# while the wire was wrong.
#
#   1. auto_options on (default) -> OPTIONS 200 + Allow + Contact, answered
#      again from the transaction cache on retransmit; MESSAGE/INVITE 405+Allow
#   2. auto_options off          -> OPTIONS silent (no 100 Trying either);
#      MESSAGE/INVITE still 405+Allow
#
# Runs the real binary against loopback — no docker, no SIPp. The parts that
# unit tests cannot reach are here: the server-transaction feed (1) and the
# transaction/auto-100 reaping that makes the drop actually silent (2).
#
# Requires: python3, a built siphon. Usage: scripts/options_fallback_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || exit 2

BINARY="${SIPHON_BIN:-$REPO_ROOT/target/release/siphon}"
CONFIG="$REPO_ROOT/sipp/nohandler/nohandler.yaml"
PROBE="$REPO_ROOT/sipp/nohandler/probe.py"
LOG="$(mktemp -t siphon-nohandler-XXXXXX.log)"
SIPHON_PID=""

cleanup() {
  [[ -n "$SIPHON_PID" ]] && kill -9 "$SIPHON_PID" >/dev/null 2>&1
  rm -f "$LOG"
}
trap cleanup EXIT

# Build if needed, the way wedge_test.sh builds its image. Incremental, so a
# repeat run is a no-op. Set SIPHON_BIN to test an existing build instead.
if [[ ! -x "$BINARY" ]]; then
  if [[ -n "${SIPHON_BIN:-}" ]]; then
    echo "error: SIPHON_BIN=$SIPHON_BIN is not an executable" >&2
    exit 2
  fi
  echo "=== building siphon (no binary at $BINARY) ==="
  if ! PYO3_PYTHON="${PYO3_PYTHON:-python3}" cargo build --release --bin siphon; then
    echo "error: build failed" >&2
    exit 2
  fi
fi

# $1 = "true"/"false" for server.auto_options, $2 = the probe's mode argument.
run_mode() {
  local auto_options="$1" mode="$2"
  echo "=== auto_options: $auto_options ==="

  SIPHON_AUTO_OPTIONS="$auto_options" PYO3_PYTHON="${PYO3_PYTHON:-python3}" \
    "$BINARY" --config "$CONFIG" >"$LOG" 2>&1 &
  SIPHON_PID=$!

  # Wait on a real SIP round-trip rather than a fixed sleep: startup compiles
  # the script, which is neither instant nor constant, and a UDP connect() to
  # an unbound port succeeds — so a socket-level check would hand the first
  # probe a silently dropped datagram.
  if ! python3 "$PROBE" wait; then
    echo "FAIL: siphon did not come up"
    cat "$LOG"
    return 2
  fi

  python3 "$PROBE" "$mode"
  local result=$?

  kill -9 "$SIPHON_PID" >/dev/null 2>&1
  wait "$SIPHON_PID" 2>/dev/null
  SIPHON_PID=""
  if (( result != 0 )); then
    echo "--- siphon log ---"
    tail -20 "$LOG"
  fi
  return $result
}

run_mode true on || exit 1
echo
run_mode false off || exit 1

echo
echo "PASS: no-handler fallback correct in both modes"
