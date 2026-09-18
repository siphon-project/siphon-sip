#!/usr/bin/env bash
# proxy_protocol_test.sh — the client address survives a REAL front.
#
# Runs a REGISTER + INVITE flow through an actual HAProxy in `send-proxy-v2`
# mode into siphon's `tls` listener, and asserts siphon attributed the traffic
# to the CALLER (192.0.2.30) rather than to HAProxy (192.0.2.20).
#
# The signal is deterministic and lives in the caller's own scenario: siphon
# copies what each consumer holds — request.source_ip, source_ip_in(), the
# stored registration's captured flow, and the contact fix_nated_register()
# rewrote — into headers on the INVITE's 200, and the caller compares each
# against its own address.  A build where the substitution never reaches those
# consumers answers with HAProxy's address, the comparison fails, and the
# scenario times out on an unreachable label -> non-zero exit -> this fails.
#
# HAProxy connecting with TLS is what makes the ordering real: the PROXY header
# is cleartext and precedes the ClientHello, so siphon must read it before its
# own handshake.
#
# Requires: docker, openssl.  Usage: scripts/proxy_protocol_test.sh
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.proxy-protocol.yaml)

# Per-run TLS material, outside the repo so nothing is ever committed. The
# certificate is not a trust decision under test — HAProxy dials the backend
# with `verify none`; siphon just needs a key pair to complete a handshake.
TLS_DIR="$(mktemp -d)"
export PROXY_PROTOCOL_TLS_DIR="$TLS_DIR"

# Where siphon writes its CDR, so the host can read the row back.
OUT_DIR="$(mktemp -d)"
export PROXY_PROTOCOL_OUT_DIR="$OUT_DIR"
chmod 0777 "$OUT_DIR"

cleanup() {
  "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true
  rm -rf "$TLS_DIR" "$OUT_DIR"
}
trap cleanup EXIT

echo "[*] Generating a throwaway server certificate."
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
  -subj "/CN=pbx.example" >/dev/null 2>&1
# The container runs as a different uid than the host user that made these.
chmod 0755 "$TLS_DIR"
chmod 0644 "$TLS_DIR/key.pem" "$TLS_DIR/cert.pem"

# CI loads sipp-siphon from the build-image job, and every siphon service in the
# compose files shares that tag, so building here would redo a ~10 minute image
# that is already present. Build only when it is absent, which is the local case.
if docker image inspect sipp-siphon:latest >/dev/null 2>&1; then
  echo "[*] Reusing the existing sipp-siphon image."
else
  echo "Building siphon image (sipp-siphon)..."
  "${COMPOSE[@]}" build siphon-proxyproto
fi

echo "=== start siphon (healthcheck-gated) + haproxy ==="
"${COMPOSE[@]}" up -d --wait siphon-proxyproto
"${COMPOSE[@]}" up -d haproxy
# HAProxy binds immediately, but give it a moment before the one-shot caller
# fires: a connection refused here would fail the run for the wrong reason.
sleep 3

echo "=== run the caller through the front ==="
rc=0
"${COMPOSE[@]}" run --rm uac-proxyproto || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "FAILED: exit ${rc} — siphon did not attribute the call to the caller"
  "${COMPOSE[@]}" logs siphon-proxyproto haproxy 2>/dev/null | tail -80 || true
  exit "${rc}"
fi

# Which address lands on a CDR row is decided inside the dispatcher, in private
# code no Rust integration test can reach, so this is the only place it is
# provable: a call behind a front has to be billed against the caller.
echo "=== assert the CDR row carries the caller, not the front ==="
CDR_FILE="${OUT_DIR}/cdr.jsonl"
deadline=$((SECONDS + 15))
while [[ ! -s "${CDR_FILE}" && ${SECONDS} -lt ${deadline} ]]; do
  sleep 1
done
if [[ ! -s "${CDR_FILE}" ]]; then
  echo "FAILED: siphon wrote no CDR row, so the consumer proved nothing"
  "${COMPOSE[@]}" logs siphon-proxyproto 2>/dev/null | tail -40 || true
  exit 1
fi
if ! grep -qE '"source_ip"[[:space:]]*:[[:space:]]*"192\.0\.2\.30"' "${CDR_FILE}"; then
  echo "FAILED: the CDR row is not attributed to the caller"
  cat "${CDR_FILE}"
  exit 1
fi
if grep -q '192\.0\.2\.20' "${CDR_FILE}"; then
  echo "FAILED: the CDR row carries the front's address"
  cat "${CDR_FILE}"
  exit 1
fi

echo "PASS: the client address survived the front (REGISTER + INVITE + CDR)"
