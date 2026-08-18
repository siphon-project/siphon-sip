#!/usr/bin/env bash
# banscan_test.sh — failed_auth_ban auto-ban regression (real instance).
#
# Two signals, one instance:
#
#   auth path — unauthenticated REGISTERs draw 401s (each records a failure) →
#   after the threshold the source IP is banned → a fresh connection from that
#   IP is dropped at accept (TransportAcl::is_allowed) before any SIP parsing.
#   A build that fails to record/enforce the ban answers the second connection
#   with a 401 → the client exits 1 → this script FAILS.
#
#   non-SIP path — a complete HTTP request on the SIP port (the vulnerability
#   scanner walking /phpinfo.php) is closed unanswered and counted as a strong
#   signal, so one probe bans the source at this config's threshold. A build
#   that classifies only *incomplete* frames queues the probe to the dispatcher
#   instead, leaving the connection open and the source unrecorded → FAILS.
#
# The instance is restarted between the two so each starts from an empty ban
# store (both stores are in-memory, and a ban lasts 60 s here).
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

fail() {
  echo "FAIL ($2): $1"
  echo "--- siphon log tail ---"
  docker logs "$CONTAINER" 2>&1 | tail -10
  exit 1
}

echo "=== run scanner client (trip ban on failed auth, then verify drop) ==="
if python3 "$DIR/banscan_client.py"; then
  echo "PASS: scanner banned at accept after repeated failed auth"
else
  fail "scanner not banned — auto-ban did not record/enforce" $?
fi

echo "=== restart siphon (empty ban store for the non-SIP probe) ==="
docker restart "$CONTAINER" >/dev/null
sleep 4

echo "=== run http probe client (probe dropped, then verify ban) ==="
if python3 "$DIR/httpprobe_client.py"; then
  echo "PASS: non-SIP probe closed unanswered and banned at accept"
else
  fail "non-SIP probe not dropped/counted — a scanner can probe indefinitely" $?
fi

exit 0
