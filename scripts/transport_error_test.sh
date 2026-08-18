#!/usr/bin/env bash
# A forwarding transport error must become a response — SIPp acceptance test.
#
# siphon relays an INVITE over TCP to a host that is up but listening on
# nothing, so the connection is refused immediately.  RFC 3261 §16.9 makes that
# a 503 on the branch, and §16.7 step 6 forwards it upstream as a 500.
#
# Before this was wired the branch went silent: the error was logged, the
# transaction was reaped, and the caller sat on its `100 Trying` until its own
# Timer F fired 32 s later.  The caller here demands a 500 within 20 s, so the
# old behaviour fails the run.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.yaml --profile transport-error)

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon-transport-error logs ---"
  "${COMPOSE[@]}" logs siphon-transport-error 2>/dev/null | tail -60 || true
  exit 1
}

# `docker compose logs` is not synchronous with the container's stdout: a line
# the container has already written can take a moment to reach the log driver.
# Grepping once, the instant the call returns, is therefore a race — it has gone
# red on a run whose own failure dump (the same logs, read 200 ms later) did
# contain the line. Poll to a deadline instead of sampling once.
wait_for_log() {
  local pattern="$1" deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if "${COMPOSE[@]}" logs siphon-transport-error 2>/dev/null | grep -q "${pattern}"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

echo "=== Transport error on forwarding must be answered (RFC 3261 §16.9 / §16.7) ==="
echo "[*] Building siphon image..."
"${COMPOSE[@]}" build siphon-transport-error

echo "[*] Starting siphon and the blackhole (up, listening on nothing)..."
"${COMPOSE[@]}" up -d transport-error-blackhole
"${COMPOSE[@]}" up -d --wait siphon-transport-error \
  || fail "siphon did not become healthy"

echo "[*] Calling through the dead next hop..."
rc=0
"${COMPOSE[@]}" run --rm sipp-transport-error-uac || rc=$?
if [[ ${rc} -ne 0 ]]; then
  fail "the caller was never answered (exit ${rc}) — the transport error did not become a response"
fi

# The 500 must be the proxy's own §16.7 downgrade, not a relayed 503.
if wait_for_log "TCP pool send failed"; then
  echo "[*] confirmed: the pool send did fail (so the 500 came from the error path)"
else
  fail "the pool send never failed — the test did not exercise the transport-error path"
fi

echo "PASS: the transport error was answered upstream as 500 instead of going silent"
