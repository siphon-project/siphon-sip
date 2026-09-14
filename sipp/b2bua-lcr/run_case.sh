#!/usr/bin/env bash
# Place one call through the LCR siphon (b2bua_lcr.py, routes from routes.json)
# and fail unless the caller and every carrier passed their scenarios, and no
# final response reached the caller a second time.
#
# The carriers carry assertions of their own (the policy-shaped INVITE, the ACK
# siphon owes their failure) and run detached, so the caller's exit code alone
# would pass a run in which one of them failed. The caller's counts come from
# the screen SIPp dumps as it quits, copied out of its container before it is
# removed (see check_final_retransmissions.py for why they are needed).
#
# siphon-b2bua-lcr and b2bua-lcr-api are expected to be up already.
#
# Usage: run_case.sh <caller scenario> <carrier service> [<carrier service> ...]
set -euo pipefail

scenario="$1"
shift

here="$(cd "$(dirname "$0")" && pwd)"
compose=(docker compose -f "$here/../docker-compose.yaml" --profile b2bua-lcr)
caller=sipp-b2bua-lcr-uac
traces="$(mktemp -d)"
trap 'rm -rf "$traces"' EXIT

"${compose[@]}" up -d --force-recreate "$@"

status=0
docker rm -f "$caller" > /dev/null 2>&1 || true
if ! "${compose[@]}" run --name "$caller" "$caller" -sf "/sipp/scenarios/$scenario"; then
  echo "$scenario: the caller scenario failed"
  status=1
fi
# The files the caller's entrypoint writes: its screen dump, its errors and its
# <log> actions (what it was sent in From and To).
if ! docker cp "$caller:/tmp/." "$traces/"; then
  echo "$scenario: nothing to copy out of the caller"
  status=1
fi
docker rm -f "$caller" > /dev/null 2>&1 || true
cat "$traces/caller-logs.log" 2> /dev/null || true
if [ "$status" != "0" ]; then
  cat "$traces/caller-errors.log" 2> /dev/null || true
fi

for carrier in "$@"; do
  code="$(timeout 60 docker wait "$carrier" || echo "no exit within 60 s")"
  if [ "$code" != "0" ]; then
    echo "$scenario: $carrier exited $code"
    docker logs "$carrier" 2>&1 | tail -40
    status=1
  fi
done

if ! python3 "$here/check_final_retransmissions.py" "$traces/caller-screen.log"; then
  status=1
fi

exit "$status"
