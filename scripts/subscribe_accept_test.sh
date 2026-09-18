#!/usr/bin/env bash
# A real TLS front, unreachable Contact, and initial + background NOTIFY.
# The supplied image must contain the current checkout; no implicit rebuild.
set -euo pipefail
cd "$(dirname "$0")/.."
export SUBSCRIBE_ACCEPT_TLS_DIR
SUBSCRIBE_ACCEPT_TLS_DIR="$(mktemp -d)"
COMPOSE=(docker compose -p siphon-subscribe-accept -f sipp/docker-compose.subscribe-accept.yaml)
cleanup() {
  "${COMPOSE[@]}" down --remove-orphans -t 3
  rm -rf "$SUBSCRIBE_ACCEPT_TLS_DIR"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout "$SUBSCRIBE_ACCEPT_TLS_DIR/key.pem" -out "$SUBSCRIBE_ACCEPT_TLS_DIR/cert.pem" \
  -subj "/CN=example.com"
cat "$SUBSCRIBE_ACCEPT_TLS_DIR/cert.pem" "$SUBSCRIBE_ACCEPT_TLS_DIR/key.pem" > "$SUBSCRIBE_ACCEPT_TLS_DIR/combined.pem"
chmod 0755 "$SUBSCRIBE_ACCEPT_TLS_DIR"
chmod 0644 "$SUBSCRIBE_ACCEPT_TLS_DIR/"*.pem
"${COMPOSE[@]}" up -d notifier front
sleep 5
if ! "${COMPOSE[@]}" run --rm subscriber; then
  "${COMPOSE[@]}" logs notifier front
  exit 1
fi
if ! SUBSCRIBE_ACCEPT_SCENARIO=subscribe_accept_expire_tls_uac.xml "${COMPOSE[@]}" run --rm subscriber; then
  "${COMPOSE[@]}" logs notifier front
  exit 1
fi
echo "PASS: TLS SUBSCRIBE accepted, changed, refreshed, unsubscribed, polled and expired"
