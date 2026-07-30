#!/usr/bin/env bash
# RFC 4475 on-the-wire regression.
#
# tests/rfc4475/corpus_tests.rs proves each torture message is accepted or
# refused per RFC 4475. This proves the consequence: that a refusal actually
# reaches the peer with the status the RFC names, rather than being decided
# correctly and then dropped on the floor.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="siphon:rfc4475-test"
CONTAINER="siphon-rfc4475-test"
DIR="$REPO_ROOT/sipp/rfc4475"

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "=== build siphon image ==="
docker build -t "$IMAGE" "$REPO_ROOT" >/dev/null

echo "=== start siphon (host net; plain config, no security filters) ==="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --network host \
  -v "$DIR/siphon-rfc4475.yaml:/etc/siphon/siphon.yaml:ro" \
  -v "$DIR:/etc/siphon/test_scripts:ro" \
  "$IMAGE" >/dev/null
sleep 4
echo "siphon status: $(docker ps --filter "name=$CONTAINER" --format '{{.Status}}')"

echo "=== send the byte-exact RFC 4475 fixtures and read what comes back ==="
if python3 "$DIR/rfc4475_client.py"; then
  echo "PASS: every fixture accepted, refused with the right status, or dropped"
  exit 0
else
  rc=$?
  if [[ $rc -eq 2 ]]; then
    echo "SETUP ERROR ($rc): siphon or the handler did not come up"
  else
    echo "FAIL ($rc): a fixture did not behave as RFC 4475 requires on the wire"
  fi
  echo "--- siphon log tail ---"
  docker logs "$CONTAINER" 2>&1 | tail -25
  exit $rc
fi
