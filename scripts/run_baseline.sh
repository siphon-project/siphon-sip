#!/usr/bin/env bash
# Run the full 16-row scale baseline and print a compact pass/fail table.
# Failures and Retransmits are correctness invariants (must be 0 on every row).
set -uo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

SIZES=("1000 250 1" "5000 1000 4" "20000 5000 4" "40000 10000 8")
LABEL="${LABEL:-baseline}"
OUT="/tmp/siphon_${LABEL}_$$"
mkdir -p "$OUT"

printf '%-6s %-4s %-16s %8s %7s %8s %6s %9s  %s\n' \
    MODE TR SIZE PEAKcps FAILED RETRANS CPU% RSS RESULT
overall=0

for mode in proxy b2bua; do
  for tr in udp tcp; do
    for size in "${SIZES[@]}"; do
      tag="${mode}_${tr}_$(echo "$size" | tr ' ' '_')"
      log="$OUT/$tag.log"
      MODE="$mode" TRANSPORT="$tr" ./scripts/scale_test.sh $size > "$log" 2>&1 || true

      failed=$(grep -oP 'Failed:\s+\K[0-9]+' "$log" | head -1)
      retr=$(grep -oP 'Retransmissions:\s+\K[0-9]+' "$log" | head -1)
      peak=$(grep -oP 'Peak CPS \(1s\):\s+~\K[0-9]+' "$log" | head -1)
      cpu=$(grep -oP 'Peak siphon CPU:\s+\K[0-9]+' "$log" | head -1)
      rss=$(grep -oP 'Peak siphon RSS:\s+\K[0-9.]+ MB' "$log" | head -1)
      wall=$(grep -oP 'Wall elapsed:\s+\K[0-9]+' "$log" | head -1)
      : "${failed:=ERR}" "${retr:=ERR}" "${peak:=ERR}" "${cpu:=?}" "${rss:=?}" "${wall:=?}"

      result=PASS
      if [ "$failed" != "0" ] || [ "$retr" != "0" ]; then result=FAIL; overall=1; fi
      if grep -q "^error" "$log" 2>/dev/null; then result=BUILD_ERR; overall=1; fi

      printf '%-6s %-4s %-16s %8s %7s %8s %5s%% %9s %7sms  %s\n' \
        "$mode" "$tr" "$size" "$peak" "$failed" "$retr" "$cpu" "$rss" "$wall" "$result"

      # Cooldown so TCP TIME_WAIT / ephemeral ports drain before the next
      # high-CPS row (b2bua churns ~2x connections per call vs proxy).
      sleep 8
    done
  done
done

echo "---"
echo "logs: $OUT"
if [ "$overall" -eq 0 ]; then echo "OVERALL: PASS (all rows 0 failures / 0 retransmits)"; else echo "OVERALL: FAIL"; fi
exit "$overall"
