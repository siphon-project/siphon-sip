#!/usr/bin/env bash
# Terminating failover across an AoR's bindings — SIPp acceptance test.
#
# Three scenarios, one fixture proxy (scripts/failover_proxy.py):
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
#   3. Non-INVITE timeout.  dave's MESSAGE is relayed to a next hop that never
#      answers.  With transaction.timeout_secs 3 the client transaction times
#      out at 3 s, not at 64*T1, and the caller must get the 408 between 2.5
#      and 5.5 s after sending (sipp/non_invite_timeout_uac.xml times it).
#
# The first two callers demand a 200, the third a 408 on time; anything else
# fails the run.
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
# CI loads sipp-siphon from the build-image job, and every siphon service in the
# compose files shares that tag, so building here would redo a ~10 minute image
# that is already present. Build only when it is absent, which is the local case.
if docker image inspect sipp-siphon:latest >/dev/null 2>&1; then
  echo "[*] Reusing the existing sipp-siphon image."
else
  echo "[*] Building siphon image..."
  "${COMPOSE[@]}" build siphon-failover
fi

echo "[*] Starting siphon..."
"${COMPOSE[@]}" up -d --wait siphon-failover || fail "siphon did not become healthy"

# ── Scenario 1: per-binding Path routing ────────────────────────────────────
echo
echo "--- 1/3: per-binding Path routing (RFC 3327 §5.3) ---"

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
echo "--- 2/3: @proxy.on_failure re-target on a single-destination relay ---"

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
"${COMPOSE[@]}" rm -sf sipp-failover-backend-primary sipp-failover-backend-backup >/dev/null 2>&1 || true

# ── Scenario 3: a non-INVITE times out at transaction.timeout_secs ──────────
echo
echo "--- 3/3: non-INVITE timeout at transaction.timeout_secs (RFC 3261 §17.1.2.2) ---"

echo "[*] Starting dave's next hop, which never answers..."
"${COMPOSE[@]}" up -d sipp-failover-silent
sleep 2

echo "[*] Messaging dave..."
rc=0
"${COMPOSE[@]}" run --rm sipp-failover-timeout-uac || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- silent next hop logs ---"
  "${COMPOSE[@]}" logs sipp-failover-silent 2>/dev/null | tail -30 || true
  fail "no 408 between 2.5 and 5.5 s (exit ${rc}) — Timer F is not transaction.timeout_secs"
fi

# SIPp's screen counts the MESSAGE once and its Timer E retransmissions apart
# (0.5 s and 1.5 s in, before the 3 s timeout): one message, two or more
# retransmissions, or the 408 was not a timeout of a retransmitting transaction.
silent_hop_was_retransmitted_to() {
  "${COMPOSE[@]}" logs "$1" 2>/dev/null | grep -aqE "> MESSAGE +1 +[2-9] "
}
deadline=$((SECONDS + 15))
until silent_hop_was_retransmitted_to sipp-failover-silent; do
  (( SECONDS < deadline )) || fail "the silent next hop did not get the MESSAGE and its retransmissions"
  sleep 0.5
done

echo "PASS: the MESSAGE to a silent next hop was retransmitted and answered 408 at the configured timeout"
echo
echo "ALL PASS"
