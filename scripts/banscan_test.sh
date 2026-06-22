#!/usr/bin/env bash
# banscan_test.sh — failed_auth_ban auto-ban regression (real instance).
#
# Proves the end-to-end glue: unauthenticated REGISTERs draw 401s (auth path
# records failures) → after the threshold the source IP is banned → a fresh
# connection from that IP is dropped at accept (TransportAcl::is_allowed) before
# any SIP parsing. A build that fails to record/enforce the ban answers the
# second connection with a 401 → the client exits 1 → this script FAILS.
#
# Requires: docker, python3. Usage: scripts/banscan_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="siphon:banscan-test"
CONTAINER="siphon-banscan-test"
DIR="$REPO_ROOT/sipp/banscan"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== build siphon image ==="
docker build -t "$IMAGE" "$REPO_ROOT" >/dev/null

echo "=== start siphon (host net; failed_auth_ban threshold=3) ==="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --network host \
  -v "$DIR/siphon-banscan.yaml:/etc/siphon/siphon.yaml:ro" \
  -v "$DIR:/etc/siphon/test_scripts:ro" \
  "$IMAGE" >/dev/null
sleep 4
echo "siphon status: $(docker ps --filter "name=$CONTAINER" --format '{{.Status}}')"

echo "=== run scanner client (trip ban, then verify drop) ==="
if python3 "$DIR/banscan_client.py"; then
  echo "PASS: scanner banned at accept after repeated failed auth"
  exit 0
else
  rc=$?
  echo "FAIL ($rc): scanner not banned — auto-ban did not record/enforce"
  echo "--- siphon log tail ---"
  docker logs "$CONTAINER" 2>&1 | tail -10
  exit 1
fi
