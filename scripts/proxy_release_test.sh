#!/usr/bin/env bash
# proxy_release_test.sh — proxy.release acceptance test (TS 24.229 §5.2.8.1.2).
#
# siphon relays one call and Record-Routes it with `dialog.proxy_release` on;
# the caller's in-dialog INFO makes the script release the call from a timer
# (scripts/proxy_release_proxy.py). Both SIPp ends then wait for siphon's own
# BYE and check it against the dialog: its tags, the callee's CSeq one above
# the caller's last request, the script's Reason. Either end missing its BYE,
# or getting a wrong one, exits non-zero.
#
# Usage:
#   scripts/proxy_release_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.yaml --profile proxy-release)

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon-release logs ---"
  "${COMPOSE[@]}" logs siphon-release 2>/dev/null | tail -80 || true
  echo "--- UAS logs ---"
  "${COMPOSE[@]}" logs sipp-release-uas 2>/dev/null | tail -40 || true
  exit 1
}

echo "=== proxy.release (TS 24.229 §5.2.8.1.2) ==="
# CI loads sipp-siphon from the build-image job; build only when it is absent,
# which is the local case.
if docker image inspect sipp-siphon:latest >/dev/null 2>&1; then
  echo "[*] Reusing the existing sipp-siphon image."
else
  echo "[*] Building siphon image..."
  "${COMPOSE[@]}" build siphon-release
fi

"${COMPOSE[@]}" up -d --wait siphon-release || fail "siphon did not become healthy"
"${COMPOSE[@]}" up -d sipp-release-uas
sleep 2

rc=0
"${COMPOSE[@]}" run --rm sipp-release-uac || rc=$?
[[ ${rc} -eq 0 ]] || fail "the caller did not get siphon's BYE (exit ${rc})"

# The callee's verdict: its container exits once its scenario has run.
uas_rc=$(docker wait "$("${COMPOSE[@]}" ps -aq sipp-release-uas)")
[[ "${uas_rc}" == "0" ]] || fail "the callee did not get siphon's BYE (exit ${uas_rc})"

echo "PASS: proxy.release sent each end its BYE from the stored dialog"
