#!/usr/bin/env bash
# route_selfid_test.sh — RFC 3261 §16.4 Route self-identity test.
#
# Proves on the wire that siphon consumes the Record-Route it inserted itself,
# so an in-dialog request is relayed rather than refused.
#
# Why the existing SIPp stack cannot show this: sipp/configs/siphon.test.yaml
# lists 172.20.0.10 and 127.0.0.1 under `domain.local`, so a Record-Route is
# recognisable even when Route recognition is keyed on served domains alone.
# This test uses a config that lists ONLY the served domain — what an operator
# actually writes for a proxy addressed by IP — and drives the whole dialog at a
# second udp listener (:5070).
#
# Scope: this covers the headline defect (self-identity built from `domain.local`
# alone). It does NOT reach the "identity misses a second listener" case — the
# plain proxy relay path stamps Record-Route from the per-transport advertised
# host/port unless a flow pin, IPsec source or `send_socket=` pin is in play, so
# arriving on :5070 still Record-Routes the first listener's port. That case
# needs a dual-stack Gm P-CSCF, flow-token MT routing, or a script pinning
# egress; it is covered by the `build_self_identity` unit tests.
#
# Deterministic, no header inspection: invite_uac.xml uses rrs="true" +
# [routes], so its BYE carries the advertised route set and the scenario waits
# for a 200. If siphon refuses its own Record-Route, the shipped script cannot
# loose-route the BYE, no 200 comes back, and the UAC exits non-zero.
#
# Usage:
#   scripts/route_selfid_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.yaml --profile routing)

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon-routing logs ---"
  "${COMPOSE[@]}" logs siphon-routing 2>/dev/null | tail -60 || true
  exit 1
}

echo "=== Route self-identity (RFC 3261 §16.4) ==="
echo "[*] Building siphon image..."
"${COMPOSE[@]}" build siphon-routing

echo "[*] Starting siphon (two udp listeners, domain.local without the address)..."
"${COMPOSE[@]}" up -d --wait siphon-routing \
  || fail "siphon did not become healthy on the second listener (:5070)"

# The identity siphon actually built, for the failure log. Recognising the
# second listener's port is the property under test.
"${COMPOSE[@]}" logs siphon-routing 2>/dev/null \
  | grep -m1 "route self-identity" || true

echo "[*] Registering bob via the second listener..."
"${COMPOSE[@]}" run --rm sipp-routing-register >/dev/null \
  || fail "bob did not register"

echo "[*] Starting UAS..."
"${COMPOSE[@]}" up -d sipp-routing-uas
sleep 2

# The UAC's exit code is the result. A clean INVITE -> 200 -> ACK -> BYE -> 200
# exits 0. We do NOT tolerate 255 here: a refused in-dialog BYE must fail.
echo "[*] Running the call (INVITE -> 200 -> ACK -> BYE -> 200)..."
rc=0
"${COMPOSE[@]}" run --rm sipp-routing-uac || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- UAS logs ---"
  "${COMPOSE[@]}" logs sipp-routing-uas 2>/dev/null | tail -40 || true
  fail "in-dialog BYE was not relayed (exit ${rc}) — siphon did not consume its own Record-Route"
fi

echo "PASS: siphon consumed its own Record-Route and relayed the in-dialog BYE"
