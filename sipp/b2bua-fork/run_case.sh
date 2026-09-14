#!/usr/bin/env bash
# Run one parallel-fork case (see b2bua_fork.py): start its two callees, place
# the call, and fail unless the caller and both callees passed.
#
# The callees carry most of the assertions (the CANCEL, the ACKs, the BYE) and
# run detached, so the caller's exit code alone would pass a run in which one of
# them failed.
#
# Usage: run_case.sh <case> <caller scenario> <callee service> <callee service>
set -euo pipefail

case_name="$1"
scenario="$2"
shift 2

compose=(docker compose -f "$(dirname "$0")/../docker-compose.yaml" --profile b2bua-fork)

"${compose[@]}" up -d --force-recreate "$@"

status=0
if ! "${compose[@]}" run --rm sipp-b2bua-fork-uac -sf "/sipp/scenarios/$scenario" -s "$case_name"; then
  echo "$case_name: the caller scenario failed"
  status=1
fi

for callee in "$@"; do
  code="$(timeout 60 docker wait "$callee" || echo "no exit within 60 s")"
  if [ "$code" != "0" ]; then
    echo "$case_name: $callee exited $code"
    docker logs "$callee" 2>&1 | tail -40
    status=1
  fi
done

exit "$status"
