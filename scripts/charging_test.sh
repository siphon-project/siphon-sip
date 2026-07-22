#!/usr/bin/env bash
# charging_test.sh — Rf + Ro charging against a real CGRateS OCS/CDF.
#
# Opt-in (requires docker), mirrors the --ipsec functional test. Brings up the
# `charging` profile (cgrates + siphon-charging + SIPp), seeds a prepaid balance
# over CGRateS' JSON-RPC, and runs two B2BUA phases:
#
#   Phase 1 (happy)  balance = 30s: a call completes normally. Asserts CGRateS
#                    accepted the CER (the Acct-Application-Id fix — a strict
#                    go-diameter peer rejects otherwise) and stored a CDR, and
#                    that Ro reserved + re-authorized the session (CCR-I/U/T).
#   Phase 2 (deny)   balance = 0:  siphon must DISCONNECT the call. The deny UAC
#                    exits 0 only if it RECEIVES a BYE from siphon; a timeout is
#                    a hard fail. Then siphon_ro_sessions must be back at 0.
#
# Ro enforcement is B2BUA-only, so siphon-charging runs the B2BUA script.
#
# Usage:  scripts/charging_test.sh          (from the repo root)
set -euo pipefail

COMPOSE="docker compose -f sipp/docker-compose.yaml --profile charging"
RPC="http://172.20.0.70:2080/jsonrpc"
METRICS="http://172.20.0.71:9090/metrics"
ACCOUNT="sip:alice@ims.example.org"   # the From-URI siphon charges (charge: orig);
                                      # pinned to a stable domain in the SIPp scenarios
                                      # so it doesn't vary with the UAC container IP

cleanup() { $COMPOSE down --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT

rpc() { # rpc <method> <params-json>
  docker run --rm --network sipp_sipnet curlimages/curl:latest -s "$RPC" \
    -d "{\"method\":\"$1\",\"params\":[$2],\"id\":1}"
}

set_balance() { # set_balance <nanoseconds>
  rpc "ApierV2.SetBalance" \
    "{\"Tenant\":\"cgrates.org\",\"Account\":\"$ACCOUNT\",\"BalanceType\":\"*voice\",\"Value\":$1}" >/dev/null
}

run_phase() { # run_phase <uac-service>
  $COMPOSE up --abort-on-container-exit --exit-code-from "$1" \
    sipp-charging-register sipp-charging-uas "$1"
  local rc=$?
  $COMPOSE rm -sf sipp-charging-register sipp-charging-uas "$1" >/dev/null 2>&1 || true
  return $rc
}

echo "== build + start cgrates + siphon-charging =="
# Build the base `siphon` service (its Dockerfile) — it tags `sipp-siphon`,
# which siphon-charging + the SIPp peers reuse. Building `siphon-charging`
# directly is a no-op (it has no build stanza) and silently reuses a stale image.
docker compose -f sipp/docker-compose.yaml build siphon >/dev/null
$COMPOSE up -d --wait cgrates siphon-charging

echo "== seed a default charger + a 30s prepaid voice balance =="
rpc "APIerSv1.SetChargerProfile" \
  '{"Tenant":"cgrates.org","ID":"DEFAULT","RunID":"*default","Weight":10}' >/dev/null || true
set_balance 30000000000

echo "== phase 1: happy call (expect completion + a stored CDR) =="
run_phase sipp-charging-uac || { echo "FAIL: happy call did not complete"; exit 1; }
CDRS="$(rpc "CDRsV1.GetCDRs" '{}')"
echo "$CDRS" | grep -q "\"Account\"" || { echo "FAIL: no CDR stored by CGRateS"; exit 1; }
echo "  ok: call completed + CDR present"

echo "== phase 2: drain balance to 0, place a call (expect siphon BYE) =="
set_balance 0
run_phase sipp-charging-deny-uac || { echo "FAIL: siphon did not disconnect the credit-less call"; exit 1; }
echo "  ok: siphon BYE'd the credit-less call"

echo "== assert siphon_ro_sessions drained back to 0 (no leaked credit sessions) =="
GAUGE="$(docker run --rm --network sipp_sipnet curlimages/curl:latest -s "$METRICS" \
  | grep '^siphon_ro_sessions ' | awk '{print $2}')"
echo "  siphon_ro_sessions = ${GAUGE:-unknown}"
[ "${GAUGE:-1}" = "0" ] || { echo "FAIL: ro sessions did not drain"; exit 1; }

echo "PASS: Rf CDR stored, Ro reserve/re-auth/disconnect verified, sessions drained."
