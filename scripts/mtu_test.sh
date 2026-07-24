#!/usr/bin/env bash
# mtu_test.sh — RFC 3261 §18.1.1 over-MTU UDP->TCP fallback docker tests.
#
# Proves, over BOTH address families, that siphon relays an over-MTU UDP
# request over TCP and keeps an under-MTU request on UDP.  The signal is
# deterministic: the over-MTU MESSAGE is relayed at a TCP-ONLY SIPp receiver
# (a 200 only comes back if siphon switched to TCP) and the small MESSAGE at a
# UDP-ONLY receiver (a 200 only comes back if siphon kept UDP).
#
# Usage:
#   scripts/mtu_test.sh          # both families
#   scripts/mtu_test.sh v4       # IPv4 only
#   scripts/mtu_test.sh v6       # IPv6 only
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.mtu.yaml)

FAMILIES="${1:-v4 v6}"

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

# One case: bring up siphon (healthcheck-gated) + the target receiver, give the
# receiver's SIPp a moment to bind (siphon's TCP reachability probe must find it
# listening), then run the one-shot UAC.  The UAC exit code is the result — a
# clean single MESSAGE transaction exits 0; anything else fails the case (we do
# NOT tolerate 255 here, so a scenario-parse error can't pass as green).
run_case() {
  local name="$1" siphon="$2" recv="$3" uac="$4"
  echo "=== ${name} ==="
  "${COMPOSE[@]}" up -d --wait "${siphon}"
  "${COMPOSE[@]}" up -d "${recv}"
  sleep 3
  local rc=0
  "${COMPOSE[@]}" run --rm "${uac}" || rc=$?
  if [[ ${rc} -ne 0 ]]; then
    echo "FAILED (${name}): exit ${rc}"
    "${COMPOSE[@]}" logs "${siphon}" "${recv}" 2>/dev/null | tail -80 || true
    exit "${rc}"
  fi
  "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true
  echo "PASS (${name})"
}

echo "Building siphon image (sipp-siphon)..."
"${COMPOSE[@]}" build siphon-mtu4

for fam in ${FAMILIES}; do
  case "${fam}" in
    v4)
      run_case "IPv4 over-MTU -> TCP"  siphon-mtu4 recv-tcp4 uac-oversized4
      run_case "IPv4 under-MTU -> UDP" siphon-mtu4 recv-udp4 uac-small4
      ;;
    v6)
      run_case "IPv6 over-MTU -> TCP"  siphon-mtu6 recv-tcp6 uac-oversized6
      run_case "IPv6 under-MTU -> UDP" siphon-mtu6 recv-udp6 uac-small6
      ;;
    *) echo "unknown family: ${fam} (use v4 and/or v6)"; exit 2 ;;
  esac
done

echo "All RFC 3261 §18.1.1 MTU tests passed for: ${FAMILIES}"
