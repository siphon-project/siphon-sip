#!/usr/bin/env bash
# Run the memory-leak regression in both modes; report PASS/FAIL per mode.
cd "$(cd "$(dirname "$0")/.." && pwd)"

echo "########## PROXY ##########"
bash scripts/mem_leak_test.sh
echo "proxy_rc=$?"

echo "########## B2BUA ##########"
MODE=b2bua bash scripts/mem_leak_test.sh
echo "b2bua_rc=$?"
