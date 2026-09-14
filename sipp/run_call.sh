#!/usr/bin/env bash
# Place one SIPp call and grade every party: start the caller and its callees
# detached, then wait for each to finish its own scenario and check its exit
# code.
#
# Why not `docker compose up --abort-on-container-exit caller callee`: that stops
# the callee the moment the caller exits. siphon answers the caller's BYE itself
# and only then forwards a BYE to the callee, so a callee stopped early never
# answers it, and siphon retransmits that BYE for 32 s (RFC 3261 Timer F). Every
# B2BUA case reaches its callee at the same registered address, so the stray BYE
# lands on the NEXT case's callee first, which aborts it: a failure in a case that
# did nothing wrong. Waiting for each callee also stops a callee's own assertions
# from passing vacuously.
#
# Everything starts in one `up`, so compose brings the dependencies (a one-shot
# REGISTER that shares the callee's address, the siphon under test) up once and
# in order.
#
# Profiles come from COMPOSE_PROFILES (comma-separated), as for docker compose.
#
# Usage: COMPOSE_PROFILES=b2bua,b2bua-cancel run_call.sh <caller service> [<callee service> ...]
set -euo pipefail

caller="$1"
shift

compose=(docker compose -f "$(dirname "$0")/docker-compose.yaml")

"${compose[@]}" up -d --force-recreate "$caller" "$@"

status=0
wait_for() {
  local service="$1" container code
  container="$("${compose[@]}" ps -a -q "$service")"
  if [ -z "$container" ]; then
    echo "$service: no container to wait for"
    status=1
    return
  fi
  code="$(timeout 90 docker wait "$container" || echo "no exit within 90 s")"
  if [ "$code" != "0" ]; then
    echo "$service exited $code"
    docker logs "$container" 2>&1 | tail -40
    status=1
  fi
}

wait_for "$caller"
for callee in "$@"; do
  wait_for "$callee"
done

exit "$status"
