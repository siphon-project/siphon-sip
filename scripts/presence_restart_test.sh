#!/usr/bin/env bash
# A reg event notifier that restarts keeps its subscriptions.
#
# Runs the real siphon binary with the registrar on Redis and
# scripts/presence_restart.py as its script, against WATCHERS UEs from
# scripts/presence_restart_watcher.py, in the order a restart happens in the
# field: register and subscribe every UE, restart siphon, wait for the
# re-registrations, then de-register every UE. Each watcher must get its
# NOTIFY in the dialog it subscribed in, with CSeq and reginfo version
# continuing above what it saw before the restart.
#
#   scripts/presence_restart_test.sh            # 500 watchers
#   WATCHERS=100 SIPHON_BIN=target/release/siphon scripts/presence_restart_test.sh
#
# Needs redis-server and python3 on the PATH and a built siphon binary
# (default: $CARGO_TARGET_DIR or target, debug profile). Starts its own Redis
# on a free port in a temporary directory and removes both when done
# (KEEP_WORK=1 keeps the directory, with both siphon logs).
set -euo pipefail

cd "$(dirname "$0")/.."
WATCHERS="${WATCHERS:-500}"
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
SIPHON_BIN="${SIPHON_BIN:-${TARGET_DIR}/debug/siphon}"
SIP_PORT="${SIP_PORT:-25060}"
UE_BASE_PORT="${UE_BASE_PORT:-26000}"

[[ -x "${SIPHON_BIN}" ]] || { echo "FAILED: no siphon binary at ${SIPHON_BIN}"; exit 1; }
command -v redis-server >/dev/null || { echo "FAILED: redis-server is not installed"; exit 1; }

WORK="$(mktemp -d)"
REDIS_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
SIPHON_PID=""

cleanup() {
  if [[ -n "${SIPHON_PID}" ]]; then kill "${SIPHON_PID}" 2>/dev/null || true; wait "${SIPHON_PID}" 2>/dev/null || true; fi
  redis-cli -p "${REDIS_PORT}" shutdown nosave >/dev/null 2>&1 || true
  if [[ -z "${KEEP_WORK:-}" ]]; then rm -r -- "${WORK:?}"; else echo "[*] kept ${WORK}"; fi
}
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon log (tail) ---"
  tail -40 "${WORK}"/siphon-*.log 2>/dev/null || true
  exit 1
}

redis-server --port "${REDIS_PORT}" --bind 127.0.0.1 --save "" --appendonly no \
  --dir "${WORK}" --daemonize yes --logfile "${WORK}/redis.log" >/dev/null
for _ in $(seq 50); do redis-cli -p "${REDIS_PORT}" ping >/dev/null 2>&1 && break; sleep 0.1; done

cat > "${WORK}/siphon.yaml" <<EOF
listen:
  udp:
    - "127.0.0.1:${SIP_PORT}"
domain:
  local:
    - "example.test"
    - "127.0.0.1"
script:
  path: "$(pwd)/scripts/presence_restart.py"
registrar:
  backend: redis
  default_expires: 600
  max_expires: 600
  redis:
    url: "redis://127.0.0.1:${REDIS_PORT}"
log:
  level: info
EOF

start_siphon() {
  "${SIPHON_BIN}" --config "${WORK}/siphon.yaml" >"${WORK}/siphon-$1.log" 2>&1 &
  SIPHON_PID=$!
}

stop_siphon() {
  kill "${SIPHON_PID}"
  wait "${SIPHON_PID}" 2>/dev/null || true
  SIPHON_PID=""
}

echo "=== A restarted reg event notifier keeps its ${WATCHERS} subscriptions ==="
start_siphon first
python3 -I scripts/presence_restart_watcher.py subscribe "${WATCHERS}" "${WORK}/state.json" \
  "${SIP_PORT}" "${UE_BASE_PORT}" || fail "the watchers could not subscribe"

stored="$(redis-cli -p "${REDIS_PORT}" --scan --pattern 'siphon:presence:*' | wc -l)"
echo "[*] subscriptions in Redis before the restart: ${stored}"

echo "[*] restarting siphon"
stop_siphon
start_siphon second
python3 -I scripts/presence_restart_watcher.py deregister "${WATCHERS}" "${WORK}/state.json" \
  "${SIP_PORT}" "${UE_BASE_PORT}" || fail "a watcher missed its NOTIFY after the restart"
grep -h "restored presence subscriptions" "${WORK}/siphon-second.log" | tail -1 || true

echo "PASS: every watcher was NOTIFYed in its dialog after the restart"
