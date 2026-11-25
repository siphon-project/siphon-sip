#!/usr/bin/env bash
# A node killed without a shutdown clears the trunk bindings it left behind when
# it restarts.
#
# Runs the real siphon binary with the registrar on Redis and a trunk from an
# HTTP source, against a SIPp upstream registrar, in the order it happens in the
# field: the trunk registers, siphon is killed with SIGKILL (no de-REGISTER),
# and it restarts with the trunk no longer listed (its lease moved to another
# node). The registrar must then receive an `Expires: 0` REGISTER on the old
# Call-ID and Contact with a higher CSeq (RFC 3261 §10.2.2, §10.2.4), challenge
# it (§22), and get the authorised retry (the credential comes from the
# source's lookup by AoR: nothing stores it, and SIPp verifies the digest against
# the password, LOOKUP_PASSWORD=wrong makes the lookup serve a wrong one and the
# test fail), which it accepts. The Redis record
# of the binding must hold no credential, and be gone at the end.
#
#   scripts/registrant_restart_test.sh
#   SIPHON_BIN=target/release/siphon scripts/registrant_restart_test.sh
#
# Needs redis-server, redis-cli, sipp and python3 on the PATH and a built siphon
# binary (default: $CARGO_TARGET_DIR or target, release profile). Starts its own
# Redis on a free port in a temporary directory and removes both when done
# (KEEP_WORK=1 keeps the directory, with the siphon and SIPp logs). No compose.
set -euo pipefail

cd "$(dirname "$0")/.."
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
SIPHON_BIN="${SIPHON_BIN:-${TARGET_DIR}/release/siphon}"
SIP_PORT=25060
REGISTRAR_PORT=25070
TOKEN="restart-test-token"
AOR="sip:trunk1@registrar.test"
INSTANCE="edge-restart-test"

[[ -x "${SIPHON_BIN}" ]] || { echo "FAILED: no siphon binary at ${SIPHON_BIN}"; exit 1; }
for tool in redis-server redis-cli sipp python3; do
  command -v "${tool}" >/dev/null || { echo "FAILED: ${tool} is not installed"; exit 1; }
done

WORK="$(mktemp -d)"
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
REDIS_PORT="$(free_port)"
SOURCE_PORT="$(free_port)"
SIPHON_PID=""
SOURCE_PID=""
SIPP_PID=""

cleanup() {
  for pid in "${SIPHON_PID}" "${SOURCE_PID}" "${SIPP_PID}"; do
    if [[ -n "${pid}" ]]; then kill "${pid}" 2>/dev/null || true; wait "${pid}" 2>/dev/null || true; fi
  done
  redis-cli -p "${REDIS_PORT}" shutdown nosave >/dev/null 2>&1 || true
  if [[ -z "${KEEP_WORK:-}" ]]; then rm -r -- "${WORK:?}"; else echo "[*] kept ${WORK}"; fi
}
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon log (tail) ---"
  tail -40 "${WORK}"/siphon-*.log 2>/dev/null || true
  echo "--- source requests ---"
  cat "${WORK}/state.requests" 2>/dev/null || true
  exit 1
}

redis-server --port "${REDIS_PORT}" --bind 127.0.0.1 --save "" --appendonly no \
  --dir "${WORK}" --daemonize yes --logfile "${WORK}/redis.log" >/dev/null
for _ in $(seq 50); do redis-cli -p "${REDIS_PORT}" ping >/dev/null 2>&1 && break; sleep 0.1; done

echo listed > "${WORK}/state"
python3 -I scripts/registrant_restart_source.py "${SOURCE_PORT}" "${WORK}/state" "${TOKEN}" \
  "${LOOKUP_PASSWORD:-secret123}" &
SOURCE_PID=$!
for _ in $(seq 50); do
  python3 -I -c "import socket,sys; socket.create_connection(('127.0.0.1',${SOURCE_PORT}),0.2)" 2>/dev/null && break
  sleep 0.1
done

cat > "${WORK}/siphon.yaml" <<EOF
listen:
  udp:
    - "127.0.0.1:${SIP_PORT}"
domain:
  local:
    - "example.test"
    - "127.0.0.1"
server:
  instance_id: "${INSTANCE}"
script:
  path: "$(pwd)/scripts/proxy_default.py"
registrar:
  backend: redis
  default_expires: 600
  max_expires: 600
  redis:
    url: "redis://127.0.0.1:${REDIS_PORT}"
registrant:
  backend: http
  default_interval: 600
  http:
    url: "http://127.0.0.1:${SOURCE_PORT}/trunks"
    lookup_url: "http://127.0.0.1:${SOURCE_PORT}/lookup?aor={aor}"
    auth_header: "Bearer ${TOKEN}"
    refresh_secs: 2
log:
  level: info
EOF

start_siphon() {
  "${SIPHON_BIN}" --config "${WORK}/siphon.yaml" >"${WORK}/siphon-$1.log" 2>&1 &
  SIPHON_PID=$!
}

# A SIPp registrar running one scenario, in the background, tracing messages.
start_registrar() {
  sipp -sf "sipp/registrant_restart_$1.xml" -i 127.0.0.1 -p "${REGISTRAR_PORT}" -m 1 \
    -nostdin -trace_msg -message_file "${WORK}/registrar-$1.msg" \
    -trace_err -error_file "${WORK}/registrar-$1.err" >"${WORK}/sipp-$1.log" 2>&1 &
  SIPP_PID=$!
}

# Wait up to $2 seconds for the SIPp registrar started for scenario $1 to end.
await_registrar() {
  for _ in $(seq $(($2 * 10))); do
    kill -0 "${SIPP_PID}" 2>/dev/null || { wait "${SIPP_PID}" && SIPP_PID="" && return 0; SIPP_PID=""; return 1; }
    sleep 0.1
  done
  return 1
}

# The value of header $2 on the $3-th REGISTER a SIPp trace ($1) received.
header_of() {
  python3 -I - "$1" "$2" "$3" <<'PY'
import re, sys
path, header, index = sys.argv[1], sys.argv[2], int(sys.argv[3])
text = open(path, encoding="latin-1").read()
blocks = re.split(r"(?m)^-{20,}.*$", text)
requests = [b for b in blocks if re.search(r"message received", b) and re.search(r"(?m)^REGISTER sip:", b)]
if index > len(requests):
    sys.exit(1)
match = re.search(rf"(?mi)^{header}:\s*(.*?)\s*$", requests[index - 1])
print(match.group(1) if match else "")
PY
}

echo "=== A killed node's trunk binding is cleared when it restarts ==="

echo "[*] first run: the trunk registers"
start_registrar first
start_siphon first
await_registrar first 40 || fail "the registrar never saw the trunk's REGISTER"

key="$(redis-cli -p "${REDIS_PORT}" --scan --pattern 'siphon:registrant:*' | head -1)"
for _ in $(seq 50); do
  [[ -n "${key}" ]] && break
  sleep 0.1
  key="$(redis-cli -p "${REDIS_PORT}" --scan --pattern 'siphon:registrant:*' | head -1)"
done
[[ -n "${key}" ]] || fail "no binding record in Redis after the registration"
echo "[*] record: ${key}"
record="$(redis-cli -p "${REDIS_PORT}" hgetall "${key}")"
for secret in secret123 line-user-7; do
  if grep -q "${secret}" <<<"${record}"; then fail "the Redis record holds '${secret}'"; fi
done

echo "[*] SIGKILL: no shutdown, no de-REGISTER"
kill -9 "${SIPHON_PID}"
wait "${SIPHON_PID}" 2>/dev/null || true
SIPHON_PID=""
redis-cli -p "${REDIS_PORT}" exists "${key}" | grep -q 1 || fail "the record is not in Redis after the kill"

echo "[*] second run: the trunk is no longer listed (its lease moved)"
echo unlisted > "${WORK}/state"
start_registrar second
start_siphon second
await_registrar second 60 \
  || fail "the registrar did not see the de-REGISTER, its challenge answered, and accept it"

first_call_id="$(header_of "${WORK}/registrar-first.msg" Call-ID 1)"
first_cseq="$(header_of "${WORK}/registrar-first.msg" CSeq 1 | cut -d' ' -f1)"
dereg_call_id="$(header_of "${WORK}/registrar-second.msg" Call-ID 1)"
dereg_cseq="$(header_of "${WORK}/registrar-second.msg" CSeq 1 | cut -d' ' -f1)"
retry_call_id="$(header_of "${WORK}/registrar-second.msg" Call-ID 2)"
retry_cseq="$(header_of "${WORK}/registrar-second.msg" CSeq 2 | cut -d' ' -f1)"
[[ -n "${first_call_id}" ]] || fail "could not read the first Call-ID from the SIPp trace"
[[ "${dereg_call_id}" == "${first_call_id}" ]] \
  || fail "the de-REGISTER is on Call-ID ${dereg_call_id}, not the old ${first_call_id}"
[[ "${retry_call_id}" == "${first_call_id}" ]] || fail "the authorised retry left the Call-ID"
first_contact="$(header_of "${WORK}/registrar-first.msg" Contact 1)"
dereg_contact="$(header_of "${WORK}/registrar-second.msg" Contact 1)"
retry_contact="$(header_of "${WORK}/registrar-second.msg" Contact 2)"
[[ -n "${first_contact}" && "${dereg_contact}" == "${first_contact}" && "${retry_contact}" == "${first_contact}" ]] \
  || fail "the de-REGISTER Contacts (${dereg_contact} / ${retry_contact}) are not the registered one (${first_contact})"
(( dereg_cseq > first_cseq )) || fail "de-REGISTER CSeq ${dereg_cseq} does not outrank ${first_cseq}"
(( retry_cseq > dereg_cseq )) || fail "retry CSeq ${retry_cseq} does not outrank ${dereg_cseq}"
grep -q "authorised=True" "${WORK}/state.requests" && grep -q "^/lookup" "${WORK}/state.requests" \
  || fail "siphon never asked the source's lookup"

for _ in $(seq 100); do
  [[ "$(redis-cli -p "${REDIS_PORT}" exists "${key}")" == "0" ]] && break
  sleep 0.1
done
[[ "$(redis-cli -p "${REDIS_PORT}" exists "${key}")" == "0" ]] || fail "the Redis record is still there"
grep -q "restart clean-up" "${WORK}"/siphon-second.log || fail "siphon never logged the clean-up"

echo "PASS: Expires: 0 on Call-ID ${first_call_id} (CSeq ${first_cseq} -> ${dereg_cseq} -> ${retry_cseq}), challenge answered from the lookup, record gone"
