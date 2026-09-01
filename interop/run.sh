#!/usr/bin/env bash
#
# Run the siphon <-> Kamailio interop suite.
#
#   interop/run.sh              # every chain
#   interop/run.sh forward      # one chain
#
# Exits non-zero if any chain fails.
#
# Why this wrapper exists rather than a bare `docker compose up`: SIPp exits 0
# when no call *failed*, which includes the case where no call ever completed.
# A run torn down early — by `--abort-on-container-exit` firing on some other
# container — therefore reads as green while proving nothing. So each chain is
# additionally required to report at least one successful call.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f interop/docker-compose.yaml)

CHAINS=("$@")
if [ ${#CHAINS[@]} -eq 0 ]; then
    CHAINS=(forward reverse cancel)
fi

# UAC service per chain — the container whose exit code decides the run.
uac_for() {
    case "$1" in
        forward) echo "interop-uac-forward" ;;
        reverse) echo "interop-uac-reverse" ;;
        cancel)  echo "interop-uac-cancel" ;;
        *) echo "unknown chain: $1" >&2; exit 2 ;;
    esac
}

cleanup() {
    for chain in "${CHAINS[@]}"; do
        "${COMPOSE[@]}" --profile "$chain" down -v --remove-orphans >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

echo "==> building the siphon image under test"
"${COMPOSE[@]}" --profile forward build siphon-forward

failures=0
for chain in "${CHAINS[@]}"; do
    uac="$(uac_for "$chain")"
    log="$(mktemp)"

    echo
    echo "==> chain: ${chain}"
    # Each chain starts from a clean stack: the SIPp endpoints run with -m 1 and
    # exit after one call, so a reused stack silently answers nothing.
    "${COMPOSE[@]}" --profile "$chain" down -v --remove-orphans >/dev/null 2>&1 || true

    status=0
    "${COMPOSE[@]}" --profile "$chain" up \
        --abort-on-container-exit --exit-code-from "$uac" >"$log" 2>&1 || status=$?

    # The cumulative "Successful call" figure from the UAC's final stats block.
    # SIPp prints `| Counter | periodic | cumulative` and compose prefixes each
    # line with the service name, so the cumulative figure is the last field
    # however many columns the prefix adds.
    # `|| true`: a chain that never got as far as printing a stats block is the
    # loudest failure there is, and grep exiting 1 under `pipefail` would abort
    # the script before it could say so.
    successful="$(grep "$uac" "$log" \
        | grep -E '\|[[:space:]]+Successful call' \
        | tail -1 \
        | awk -F'|' '{gsub(/[^0-9]/, "", $NF); print $NF}' || true)"
    successful="${successful:-0}"

    if [ "$status" -ne 0 ] || [ "$successful" -lt 1 ]; then
        echo "FAIL ${chain}: exit=${status} successful_calls=${successful}"
        echo "---- last 60 lines ----"
        tail -60 "$log"
        failures=$((failures + 1))
    else
        echo "PASS ${chain}: ${successful} successful call(s)"
    fi
    rm -f "$log"
done

echo
if [ "$failures" -ne 0 ]; then
    echo "${failures} chain(s) failed"
    exit 1
fi
echo "all chains passed"
