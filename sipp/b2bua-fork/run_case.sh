#!/usr/bin/env bash
# Run one case (see b2bua_fork.py): start its callees, place the call, and fail
# unless the caller and every callee passed.
#
# The callees carry most of the assertions (the CANCEL, the ACKs, the BYE) and
# run detached, so the caller's exit code alone would pass a run in which one of
# them failed.
#
# The @b2bua.on_failure cases (b2bua-on-failure/b2bua_on_failure.py) run the same
# way against their own siphon, with SIPP_PROFILE=b2bua-on-failure and
# SIPP_CALLER=sipp-b2bua-on-failure-uac.
#
# Usage: run_case.sh <case> <caller scenario> <callee service> [<callee service> ...]
set -euo pipefail

case_name="$1"
scenario="$2"
shift 2

profile="${SIPP_PROFILE:-b2bua-fork}"
caller="${SIPP_CALLER:-sipp-b2bua-fork-uac}"

compose=(docker compose -f "$(dirname "$0")/../docker-compose.yaml" --profile "$profile")

"${compose[@]}" up -d --force-recreate "$@"

status=0
if ! "${compose[@]}" run --rm "$caller" -sf "/sipp/scenarios/$scenario" -s "$case_name"; then
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
