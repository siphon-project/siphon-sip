#!/usr/bin/env bash
# wedge_test.sh — outbound-drain / accept() wedge regression (real instance).
#
# Reproduces the production wedge black-box against a REAL siphon container at
# --cpus 0.5 (same shape as prod), with host networking (so a non-reading peer
# directly backs up siphon's send buffer rather than a docker-NAT buffer):
#
#   1. baseline probe (no stuck client) -> must get 200 OK   (setup sanity)
#   2. a non-reading peer floods OPTIONS and stops reading   (the trigger)
#   3. probe again on a fresh connection                     (the assertion)
#
# On a BUGGY build (outbound distributor parks in send().await while holding the
# connection-map shard guard) the stuck peer stalls the single drain task and the
# probe times out -> FAIL. On a FIXED build the distributor try_sends and sheds
# the stuck peer, so the probe is answered -> PASS.
#
# Verified: exit 1 on the pre-fix transport drain, exit 0 with the try_send fix.
#
# Requires: docker, python3 on the host. Usage: scripts/wedge_test.sh
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="siphon:wedge-test"
CONTAINER="siphon-wedge-test"
WEDGE_DIR="$REPO_ROOT/sipp/wedge"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  [[ -n "${STUCK_PID:-}" ]] && kill "$STUCK_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== build siphon image ==="
docker build -t "$IMAGE" "$REPO_ROOT" >/dev/null

echo "=== start siphon (host net, --cpus 0.5, same shape as prod) ==="
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" --network host --cpus 0.5 \
  -v "$WEDGE_DIR/wedge.yaml:/etc/siphon/siphon.yaml:ro" \
  -v "$WEDGE_DIR:/etc/siphon/test_scripts:ro" \
  "$IMAGE" >/dev/null
sleep 4
echo "siphon status: $(docker ps --filter "name=$CONTAINER" --format '{{.Status}}')"

echo "=== baseline probe (no stuck client, must succeed) ==="
if ! python3 "$WEDGE_DIR/probe.py"; then
  echo "FAIL: baseline probe did not get a response — setup is broken (not a wedge)"
  exit 2
fi

echo "=== launch non-reading peer (the trigger) ==="
python3 "$WEDGE_DIR/stuck_client.py" 127.0.0.1 5060 2000 &
STUCK_PID=$!
sleep 14   # let siphon queue large replies to the stuck conn until a buggy drain stalls

echo "=== probe while the stuck peer holds (the assertion) ==="
if python3 "$WEDGE_DIR/probe.py"; then
  echo "PASS: probe answered while a non-reading peer is backed up — drain not wedged"
  exit 0
else
  echo "FAIL: probe got no response — outbound drain wedged by a single non-reading peer"
  echo "--- siphon log tail ---"
  docker logs "$CONTAINER" 2>&1 | tail -8
  exit 1
fi
