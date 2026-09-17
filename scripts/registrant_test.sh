#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.yaml --profile registrant)

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon-registrant logs ---"
  "${COMPOSE[@]}" logs siphon-registrant 2>/dev/null | tail -60 || true
  echo "--- sipp-registrant-registrar logs ---"
  "${COMPOSE[@]}" logs sipp-registrant-registrar 2>/dev/null | tail -40 || true
  exit 1
}

echo "=== Removing an outbound registration must de-register it (RFC 3261 §10.2.2) ==="
if docker image inspect sipp-siphon:latest >/dev/null 2>&1; then
  echo "[*] Reusing the existing sipp-siphon image."
else
  echo "[*] Building siphon image..."
  "${COMPOSE[@]}" build siphon-registrant
fi

# The registrar first: it is a UAS, so it has to be listening before siphon's
# first REGISTER rather than picking it up on a retry.
echo "[*] Starting the upstream registrar..."
"${COMPOSE[@]}" up -d sipp-registrant-registrar

echo "[*] Starting siphon with one configured trunk..."
"${COMPOSE[@]}" up -d --wait siphon-registrant \
  || fail "siphon did not become healthy"

# The scenario completes only after both REGISTERs arrive: the initial one with
# a non-zero Expires, then the Expires: 0 that removing the trunk must send.
echo "[*] Waiting for the registration and its de-registration..."
rc=0
timeout 90 docker wait sipp-registrant-registrar >/tmp/registrant_rc.$$ 2>/dev/null || rc=$?
if [[ ${rc} -ne 0 ]]; then
  fail "the registrar scenario did not finish — the de-REGISTER never arrived"
fi
scenario_rc=$(cat /tmp/registrant_rc.$$ 2>/dev/null || echo 1)
rm -f /tmp/registrant_rc.$$
if [[ "${scenario_rc}" != "0" ]]; then
  fail "the registrar scenario failed (exit ${scenario_rc}) — check the Expires assertions"
fi

# The de-registration belongs to the registration it clears (§10.2.4), so both
# REGISTERs share one Call-ID. The scenario received them as a single SIPp call,
# which is that assertion; confirm siphon logged the send rather than only the
# removal, so a passing scenario cannot be a coincidence of timing.
if "${COMPOSE[@]}" logs siphon-registrant 2>/dev/null | grep -q "de-REGISTER for a removed registrant"; then
  echo "[*] confirmed: siphon sent the de-registration for the removed trunk"
else
  fail "siphon never logged sending a de-REGISTER — the scenario passed for the wrong reason"
fi

echo "PASS: removing a trunk cleared its binding upstream with Expires: 0"
