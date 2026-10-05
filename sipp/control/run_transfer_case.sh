#!/usr/bin/env bash
# Run one `control-transfer` case (see transfer_routes.py for the list): start
# its parties, place the call, and fail unless the caller, every party, the
# control application's verdict for the case and the Call-IDs all passed.
#
# The first half is b2bua-fork/run_case.sh's: the parties carry most of the
# wire assertions and run detached, so the caller's exit code alone would pass
# a run in which one of them failed. Two things are added, because the SIP wire
# cannot show them:
#
#   * the application's CONTROL-VERDICT for the case, which carries the replies
#     and events it checked. A verdict that never appears is a failure too: it
#     is what an application that was never handed the call looks like;
#   * the Call-IDs. Each party echoes the Call-ID of the INVITE it received
#     (`WIRE-CALL-ID`), and the application prints the ones it was told
#     (`TRANSFER-FACT`). A leg's Call-ID is siphon's own and exists nowhere
#     else, so comparing the two is the only way to tie an event to the dialog
#     it claims to be about, and to show two contacts were rung on dialogs of
#     their own.
#
# The stack must be up: siphon-control-transfer and control-transfer-app.
#
# Usage: run_transfer_case.sh <case> <caller scenario> <party service> [<party service> ...]
set -euo pipefail

case_name="$1"
scenario="$2"
shift 2

compose=(docker compose -f "$(dirname "$0")/../docker-compose.yaml" --profile control-transfer)
app="sipp-control-transfer-app"

# Parties left over from an earlier case would hold the address this case's
# parties are about to be given.
docker rm -f \
  sipp-control-transfer-ringing-phone sipp-control-transfer-trying-phone \
  sipp-control-transfer-late-ringing-phone sipp-control-transfer-late-answering-phone \
  sipp-control-transfer-referrer-phone sipp-control-transfer-target \
  sipp-control-transfer-controller-referrer-phone sipp-control-transfer-silent-target \
  sipp-control-transfer-callee-phone sipp-control-transfer-answering-contact \
  sipp-control-transfer-cancelled-contact sipp-control-transfer-busy-contact \
  sipp-control-transfer-unavailable-contact >/dev/null 2>&1 || true

# Only this run's lines count: the application outlives the case. The second
# of waiting puts an earlier run's verdict outside the window `--since` opens.
sleep 1
started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

"${compose[@]}" up -d --force-recreate "$@"

# SIPp's own Call-ID is `<call>-<pid>@<address>`, and in a container that is
# the same string for every caller of every case. siphon would take a call
# that reuses the Call-ID of one it is still holding for that call, so each
# run's is its own.
status=0
if ! "${compose[@]}" run --rm sipp-control-transfer-uac \
    -sf "/sipp/scenarios/$scenario" -s "$case_name" \
    -cid_str "%u-%p-$case_name-$(date +%s)@%s"; then
  echo "$case_name: the caller scenario failed"
  status=1
fi

for party in "$@"; do
  code="$(timeout 60 docker wait "$party" || echo "no exit within 60 s")"
  if [ "$code" != "0" ]; then
    echo "$case_name: $party exited $code"
    docker logs "$party" 2>&1 | tail -40
    status=1
  fi
done

# The verdict is printed when the case's last event (the StasisEnd) has
# arrived, which can be a moment after the caller's own scenario finished.
verdict=""
for _ in $(seq 1 30); do
  verdict="$(docker logs --since "$started" "$app" 2>&1 \
    | grep 'CONTROL-VERDICT' | grep "\"case\": \"$case_name\"" | tail -1 || true)"
  [ -n "$verdict" ] && break
  sleep 1
done
if [ -z "$verdict" ]; then
  echo "$case_name: no CONTROL-VERDICT — the control application never completed the case"
  docker logs --since "$started" "$app" 2>&1 | tail -40
  status=1
elif grep -q '"pass": false' <<<"$verdict"; then
  echo "$case_name: the control application's checks failed:"
  echo "$verdict"
  status=1
else
  echo "$case_name: $verdict"
fi

# The Call-IDs a party echoed, one per INVITE it received.
wire_call_ids() {
  docker logs "$1" 2>&1 | sed -n 's/^WIRE-CALL-ID \([^[:space:]]*\).*$/\1/p'
}

# A value the application printed for this case.
fact() {
  docker logs --since "$started" "$app" 2>&1 \
    | grep 'TRANSFER-FACT' | grep "\"case\": \"$case_name\"" \
    | sed -n "s/.*\"name\": \"$1\", \"value\": \"\([^\"]*\)\".*/\1/p" | tail -1
}

# Fail unless `$2` is non-empty and equal to `$3`.
same() {
  if [ -z "$2" ] || [ "$2" != "$3" ]; then
    echo "$case_name: $1: the wire has '$2', the application was told '$3'"
    status=1
  else
    echo "$case_name: $1: $2"
  fi
}

# Fail unless `$2` and `$3` are both non-empty and different.
distinct() {
  if [ -z "$2" ] || [ -z "$3" ] || [ "$2" = "$3" ]; then
    echo "$case_name: $1: expected two different Call-IDs, got '$2' and '$3'"
    status=1
  else
    echo "$case_name: $1: $2 / $3"
  fi
}

case "$case_name" in
  cancel-dial)
    # Two dials, so each phone was rung twice, on a dialog of its own each time.
    for phone in sipp-control-transfer-ringing-phone sipp-control-transfer-trying-phone; do
      distinct "$phone was rung on a new dialog by the second dial" \
        "$(wire_call_ids "$phone" | sed -n 1p)" "$(wire_call_ids "$phone" | sed -n 2p)"
    done
    ;;
  cancel-late-ringing|cancel-late-answer)
    # One phone, rung once: the dialog its late response was dealt with on is
    # the one the dial named.
    same "DialBranch named the dialog the phone was rung on" \
      "$(wire_call_ids "$1" | sed -n 1p)" "$(fact leg_sip_call_id)"
    ;;
  refer-callee)
    referrer="$(wire_call_ids sipp-control-transfer-referrer-phone | sed -n 1p)"
    target="$(wire_call_ids sipp-control-transfer-target | sed -n 1p)"
    same "TransferRequested named the referrer's own dialog" \
      "$referrer" "$(fact referrer_sip_call_id)"
    same "PeerReplaced named the transfer target's dialog" \
      "$target" "$(fact target_sip_call_id)"
    distinct "the referrer and the target are on dialogs of their own" "$referrer" "$target"
    ;;
  replace-aor)
    answering="$(wire_call_ids sipp-control-transfer-answering-contact | sed -n 1p)"
    cancelled="$(wire_call_ids sipp-control-transfer-cancelled-contact | sed -n 1p)"
    distinct "each contact of the AoR was rung on a dialog of its own" "$answering" "$cancelled"
    same "PeerReplaced named the contact that answered" \
      "$answering" "$(fact target_sip_call_id)"
    ;;
esac

exit "$status"
