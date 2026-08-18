#!/usr/bin/env bash
# Terminating failover across an AoR's bindings — SIPp acceptance test.
#
# Two scenarios, one fixture proxy (scripts/failover_proxy.py):
#
#   1. Per-binding Path routing.  bob has two live bindings registered through
#      different edge proxies (different RFC 3327 Path tokens).  The first
#      edge answers 404 — its binding is gone.  The sequential fork's second
#      branch must be routed by the *second* binding's Path and reach the other
#      edge.  If every branch inherits branch 0's route set, the second branch
#      is delivered back to the same dead edge and the caller gets the 404.
#
#   2. Failure re-targeting.  carol's primary backend rejects; the backup is
#      only reachable from @proxy.on_failure.  The first attempt is a
#      single-destination request.relay() — no fork, no aggregator — so the
#      call completes only if the handler runs for a plain relay AND its
#      request.relay() actually re-sends.
#
# Both callers demand a 200; anything else fails the run.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.yaml --profile failover)

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon-failover logs ---"
  "${COMPOSE[@]}" logs siphon-failover 2>/dev/null | tail -80 || true
  exit 1
}

echo "=== Terminating failover across an AoR's bindings ==="
echo "[*] Building siphon image..."
"${COMPOSE[@]}" build siphon-failover

echo "[*] Starting siphon..."
"${COMPOSE[@]}" up -d --wait siphon-failover || fail "siphon did not become healthy"

# ── Scenario 1: per-binding Path routing ────────────────────────────────────
echo
echo "--- 1/2: per-binding Path routing (RFC 3327 §5.3) ---"

echo "[*] Registering bob's two bindings (Path token-a q=1.0, token-b q=0.5)..."
"${COMPOSE[@]}" run --rm sipp-failover-register-a >/dev/null \
  || fail "binding A did not register"
"${COMPOSE[@]}" run --rm sipp-failover-register-b >/dev/null \
  || fail "binding B did not register"

echo "[*] Starting both edges (.90 answers 404, .91 answers 200)..."
"${COMPOSE[@]}" up -d sipp-failover-reject sipp-failover-answer
sleep 2

echo "[*] Calling bob..."
rc=0
"${COMPOSE[@]}" run --rm sipp-failover-uac || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- dead edge (.90) logs ---"
  "${COMPOSE[@]}" logs sipp-failover-reject 2>/dev/null | tail -30 || true
  echo "--- live edge (.91) logs ---"
  "${COMPOSE[@]}" logs sipp-failover-answer 2>/dev/null | tail -30 || true
  fail "the call was not answered (exit ${rc}) — the failover branch did not reach binding B's edge"
fi

# The live edge must actually have been rung, and the dead one must have been
# tried first.  Without both, the test would also pass if siphon had answered
# the call itself or had only ever contacted one edge.
edge_received_invite() {
  "${COMPOSE[@]}" logs "$1" 2>/dev/null | grep -a "> INVITE" | grep -qE "INVITE +[1-9]"
}

# `docker compose logs` is not synchronous with a container's stdout: a line the
# container has already written can take a moment to reach the log driver, so
# grepping once the instant a call returns is a race. Poll to a deadline for the
# assertions that expect a line to BE there.
wait_edge_received_invite() {
  local deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if edge_received_invite "$1"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}
wait_edge_received_invite sipp-failover-reject \
  || fail "binding A's edge never received the INVITE — branch 0 was not routed by its Path"
wait_edge_received_invite sipp-failover-answer \
  || fail "binding B's edge never received the INVITE — the failover branch reused binding A's route set"

"${COMPOSE[@]}" rm -sf sipp-failover-reject sipp-failover-answer >/dev/null 2>&1 || true
echo "PASS: each fork branch was routed through its own binding's Path"

# ── Scenario 2: failure re-targeting on a single relay ──────────────────────
echo
echo "--- 2/2: @proxy.on_failure re-target on a single-destination relay ---"

echo "[*] Starting carol's primary (rejects) and backup (answers) backends..."
"${COMPOSE[@]}" up -d sipp-failover-backend-primary sipp-failover-backend-backup
sleep 2

echo "[*] Calling carol..."
rc=0
"${COMPOSE[@]}" run --rm sipp-failover-retarget-uac || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- primary backend logs ---"
  "${COMPOSE[@]}" logs sipp-failover-backend-primary 2>/dev/null | tail -30 || true
  echo "--- backup backend logs ---"
  "${COMPOSE[@]}" logs sipp-failover-backend-backup 2>/dev/null | tail -30 || true
  fail "the call was not answered (exit ${rc}) — on_failure did not re-target the relay"
fi

wait_edge_received_invite sipp-failover-backend-primary \
  || fail "the primary backend never received the INVITE"
wait_edge_received_invite sipp-failover-backend-backup \
  || fail "the backup backend never received the INVITE — on_failure's request.relay() did not re-send"

echo "PASS: on_failure fired for a single-destination relay and its retry reached the backup"
echo
echo "ALL PASS"
