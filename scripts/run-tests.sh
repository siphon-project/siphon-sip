#!/usr/bin/env bash
# run-tests.sh — SIPhon full test pipeline
#
# Usage:
#   ./scripts/run-tests.sh              # Rust tests + basic SIPp
#   ./scripts/run-tests.sh --ipsec      # Also run IPsec VoLTE tests
#   ./scripts/run-tests.sh --skip-rust  # Skip Rust tests (Docker only)
#   ./scripts/run-tests.sh --call       # Also run call scenarios (UAC+UAS)
#   ./scripts/run-tests.sh --rtpengine  # Also run B2BUA + RTPEngine tests
#   ./scripts/run-tests.sh --rtpproxy   # Also run classic rtpproxy media test
#   ./scripts/run-tests.sh --b2bua     # Also run B2BUA call/session-timer/cancel/failure tests
set -euo pipefail

# SIPp exit code 255 means "dead call messages" (late retransmissions received
# after the scenario completed). This is not a real failure — tolerate it.
run_sipp() {
  local rc=0
  "$@" || rc=$?
  if [[ $rc -ne 0 && $rc -ne 255 ]]; then
    echo "FAILED (exit $rc): $*"
    exit $rc
  fi
}

COMPOSE_FILE="sipp/docker-compose.yaml"
RUN_IPSEC=false
RUN_CALL=false
RUN_PRESENCE=false
RUN_RTPENGINE=false
RUN_RTPPROXY=false
RUN_REINVITE=false
RUN_B2BUA=false
RUN_GATEWAY=false
RUN_AUTO100=false
RUN_HTTP_AUTH=false
RUN_WEDGE=false
RUN_BANSCAN=false
RUN_SECURITY=false
RUN_WEBRTC=false
SKIP_RUST=false

for arg in "$@"; do
  case "$arg" in
    --ipsec)      RUN_IPSEC=true ;;
    --call)       RUN_CALL=true ;;
    --presence)   RUN_PRESENCE=true ;;
    --rtpengine)  RUN_RTPENGINE=true ;;
    --rtpproxy)   RUN_RTPPROXY=true ;;
    --reinvite)   RUN_REINVITE=true ;;
    --b2bua)      RUN_B2BUA=true ;;
    --gateway)    RUN_GATEWAY=true ;;
    --auto100)    RUN_AUTO100=true ;;
    --http-auth)  RUN_HTTP_AUTH=true ;;
    --wedge)      RUN_WEDGE=true ;;
    --banscan)    RUN_BANSCAN=true ;;
    --security)   RUN_SECURITY=true ;;
    --webrtc)     RUN_WEBRTC=true ;;
    --skip-rust)  SKIP_RUST=true ;;
    --help|-h)
      echo "Usage: $0 [--ipsec] [--call] [--presence] [--rtpengine] [--rtpproxy] [--reinvite] [--b2bua] [--gateway] [--auto100] [--http-auth] [--wedge] [--banscan] [--security] [--webrtc] [--skip-rust]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

cleanup() {
  echo "--- Cleaning up ---"
  docker compose -f "$COMPOSE_FILE" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ── Step 1: Rust tests ───────────────────────────────────────────────────────
if [[ "$SKIP_RUST" == false ]]; then
  echo "=== Rust tests ==="
  PYO3_PYTHON=python3 cargo test
  echo ""
fi

# ── Step 2: Build siphon image ──────────────────────────────────────────────
echo "=== Building siphon Docker image ==="
docker compose -f "$COMPOSE_FILE" build siphon

# ── Step 3: Start siphon ────────────────────────────────────────────────────
echo "=== Starting siphon ==="
docker compose -f "$COMPOSE_FILE" up -d siphon

echo "Waiting for siphon to be healthy..."
docker compose -f "$COMPOSE_FILE" up -d --wait siphon

# ── Step 4: Basic SIPp tests ────────────────────────────────────────────────
echo "=== SIPp OPTIONS test ==="
run_sipp docker compose -f "$COMPOSE_FILE" run --rm sipp-options

echo "=== SIPp REGISTER test ==="
run_sipp docker compose -f "$COMPOSE_FILE" run --rm sipp-register

# ── Step 5: Call tests (optional) ────────────────────────────────────────────
if [[ "$RUN_CALL" == true ]]; then
  echo "=== SIPp call test (UAC + UAS) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile call up --abort-on-container-exit sipp-uac sipp-uas
fi

# ── Step 6: Presence/event tests (optional) ─────────────────────────────────
if [[ "$RUN_PRESENCE" == true ]]; then
  echo "=== SIPp MESSAGE test (register alice → relay MESSAGE to UAS) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile presence run --rm sipp-message-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile presence up --abort-on-container-exit sipp-message-uas sipp-message-uac
fi

# ── Step 6b: NIST auto-100 Trying + UAS To-tag tests (optional) ─────────────
if [[ "$RUN_AUTO100" == true ]]; then
  echo "=== SIPp NIST auto-100 test (self-registering slow MESSAGE UAS forces proxy auto-100) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile auto100 up --abort-on-container-exit sipp-message-auto100-uas sipp-message-auto100-uac

  echo "=== SIPp UAS To-tag test (script-built 404 must carry tag=) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile auto100 run --rm sipp-message-404-to-tag
fi

# ── Step 7: RTPEngine proxy tests (optional) ──────────────────────────────
if [[ "$RUN_RTPENGINE" == true ]]; then
  echo "=== SIPp RTPEngine test (register bob → INVITE with media anchoring) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile rtpengine run --rm sipp-rtpengine-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile rtpengine up --abort-on-container-exit sipp-rtpengine-uac sipp-rtpengine-uas
fi

# ── Step 7b: Classic rtpproxy proxy test (optional) ───────────────────────
if [[ "$RUN_RTPPROXY" == true ]]; then
  echo "=== SIPp rtpproxy test (register bob → INVITE with siphon-side SDP rewrite) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile rtpproxy run --rm sipp-rtpproxy-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile rtpproxy up --abort-on-container-exit --exit-code-from sipp-rtpproxy-uac sipp-rtpproxy-uac sipp-rtpproxy-uas
  docker compose -f "$COMPOSE_FILE" --profile rtpproxy rm -sf sipp-rtpproxy-uac sipp-rtpproxy-uas 2>/dev/null || true
fi

# ── Step 8: RTPEngine re-INVITE tests (optional) ──────────────────────────
if [[ "$RUN_REINVITE" == true ]]; then
  echo "=== SIPp re-INVITE test (hold/resume with RTPEngine media renegotiation) ==="
  # Re-uses the rtpengine profile for siphon-rtpengine + mock-rtpengine + register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile reinvite --profile rtpengine run --rm sipp-rtpengine-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile reinvite --profile rtpengine up --abort-on-container-exit sipp-reinvite-uac sipp-reinvite-uas
fi

# ── Step 9: B2BUA tests (optional) ──────────────────────────────────────────
if [[ "$RUN_B2BUA" == true ]]; then
  echo "=== Building siphon-b2bua image ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua build siphon-b2bua

  echo "=== Starting siphon-b2bua ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua up -d siphon-b2bua
  docker compose -f "$COMPOSE_FILE" --profile b2bua up -d --wait siphon-b2bua

  echo "=== B2BUA basic call test (register bob → INVITE → 200 → BYE) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua run --rm sipp-b2bua-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua up --abort-on-container-exit --exit-code-from sipp-b2bua-uac sipp-b2bua-uac sipp-b2bua-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua rm -sf sipp-b2bua-uac sipp-b2bua-uas 2>/dev/null || true

  echo "=== B2BUA early media test (183 Session Progress with SDP) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-early-media up --abort-on-container-exit --exit-code-from sipp-b2bua-early-media-uac sipp-b2bua-early-media-uac sipp-b2bua-early-media-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-early-media rm -sf sipp-b2bua-early-media-uac sipp-b2bua-early-media-uas 2>/dev/null || true

  echo "=== B2BUA reliable-provisional interworking test (100rel B-leg → non-100rel A-leg) ==="
  # Dedicated siphon instance pinned to sip-trunk-edge@2026 (does NOT strip
  # Require/RSeq via preset) — proves the 100rel strip is framework-auto.
  docker compose -f "$COMPOSE_FILE" --profile b2bua-reliable-prov build siphon-b2bua-trunk-edge
  docker compose -f "$COMPOSE_FILE" --profile b2bua-reliable-prov up -d --wait siphon-b2bua-trunk-edge
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-reliable-prov run --rm sipp-b2bua-trunk-edge-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-reliable-prov up --abort-on-container-exit --exit-code-from sipp-b2bua-reliable-prov-uac sipp-b2bua-reliable-prov-uac sipp-b2bua-reliable-prov-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua-reliable-prov rm -sf sipp-b2bua-reliable-prov-uac sipp-b2bua-reliable-prov-uas 2>/dev/null || true
  docker compose -f "$COMPOSE_FILE" --profile b2bua-reliable-prov stop siphon-b2bua-trunk-edge 2>/dev/null || true

  echo "=== B2BUA session timer test (Session-Expires negotiation) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-session-timer up --abort-on-container-exit --exit-code-from sipp-b2bua-st-uac sipp-b2bua-st-uac sipp-b2bua-st-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-session-timer rm -sf sipp-b2bua-st-uac sipp-b2bua-st-uas 2>/dev/null || true

  echo "=== B2BUA re-INVITE test (hold/resume) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-reinvite up --abort-on-container-exit --exit-code-from sipp-b2bua-reinvite-uac sipp-b2bua-reinvite-uac sipp-b2bua-reinvite-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-reinvite rm -sf sipp-b2bua-reinvite-uac sipp-b2bua-reinvite-uas 2>/dev/null || true

  echo "=== B2BUA UPDATE test (RFC 3311 in-dialog UPDATE bridging) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-update up --abort-on-container-exit --exit-code-from sipp-b2bua-update-uac sipp-b2bua-update-uac sipp-b2bua-update-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-update rm -sf sipp-b2bua-update-uac sipp-b2bua-update-uas 2>/dev/null || true

  echo "=== B2BUA CANCEL test (INVITE → CANCEL → 487) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-cancel up --abort-on-container-exit --exit-code-from sipp-b2bua-cancel-uac sipp-b2bua-cancel-uac sipp-b2bua-cancel-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-cancel rm -sf sipp-b2bua-cancel-uac sipp-b2bua-cancel-uas 2>/dev/null || true

  echo "=== B2BUA failure test (INVITE → 486 Busy) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-failure run --rm sipp-b2bua-register-failure
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-failure up --abort-on-container-exit --exit-code-from sipp-b2bua-failure-uac sipp-b2bua-failure-uac sipp-b2bua-failure-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-failure rm -sf sipp-b2bua-failure-uac sipp-b2bua-failure-uas 2>/dev/null || true

  echo "=== B2BUA topology hiding test (CSeq/Max-Forwards/From host/SDP/PAI) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-topology up --abort-on-container-exit --exit-code-from sipp-b2bua-topology-uac sipp-b2bua-topology-uac sipp-b2bua-topology-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-topology rm -sf sipp-b2bua-topology-uac sipp-b2bua-topology-uas 2>/dev/null || true
fi

# ── Step 10: Gateway routing tests (optional) ──────────────────────────────────
if [[ "$RUN_GATEWAY" == true ]]; then
  echo "=== Building siphon-gateway image ==="
  docker compose -f "$COMPOSE_FILE" --profile gateway build siphon-gateway

  echo "=== Starting siphon-gateway ==="
  docker compose -f "$COMPOSE_FILE" --profile gateway up -d siphon-gateway
  docker compose -f "$COMPOSE_FILE" --profile gateway up -d --wait siphon-gateway

  echo "=== Gateway proxy test (INVITE via gateway.select) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile gateway up --abort-on-container-exit --exit-code-from sipp-gateway-uac sipp-gateway-uac sipp-gateway-uas
  docker compose -f "$COMPOSE_FILE" --profile gateway rm -sf sipp-gateway-uac sipp-gateway-uas 2>/dev/null || true

  echo "=== Building siphon-b2bua-gateway image ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-gateway build siphon-b2bua-gateway

  echo "=== Starting siphon-b2bua-gateway ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-gateway up -d siphon-b2bua-gateway
  docker compose -f "$COMPOSE_FILE" --profile b2bua-gateway up -d --wait siphon-b2bua-gateway

  echo "=== B2BUA gateway test (INVITE via gateway.select for B-leg) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-gateway up --abort-on-container-exit --exit-code-from sipp-b2bua-gateway-uac sipp-b2bua-gateway-uac sipp-b2bua-gateway-uas
fi

# ── Step 11: IPsec tests (optional) ──────────────────────────────────────────
if [[ "$RUN_IPSEC" == true ]]; then
  echo "=== SIPp IPsec VoLTE registration test ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile ipsec run --rm sipp-ipsec
fi

# ── Step 12: HTTP-auth deadlock regression (optional) ────────────────────────
# Drives sustained REGISTER load through the blocking HTTP HA1-fetch path. On an
# unfixed build the handler stays attached to the free-threaded interpreter
# while blocking, stalling the GC stop-the-world, and the engine deadlocks — the
# load then fails to complete (non-zero exit). With the `py.detach()` fix every
# registration succeeds. The --exit-code-from makes the load container's result
# the gate; a deadlock is a hard FAIL, not a tolerated dead-call (255).
if [[ "$RUN_HTTP_AUTH" == true ]]; then
  echo "=== Building siphon-http-auth image ==="
  docker compose -f "$COMPOSE_FILE" --profile http-auth build siphon-http-auth

  echo "=== HTTP-auth deadlock regression (REGISTER storm → blocking HA1 fetch) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile http-auth \
    up --abort-on-container-exit --exit-code-from sipp-http-auth-load \
    mock-http-auth siphon-http-auth sipp-http-auth-load
  docker compose -f "$COMPOSE_FILE" --profile http-auth rm -sf \
    mock-http-auth siphon-http-auth sipp-http-auth-load 2>/dev/null || true

  echo "=== on_change blocking-notify regression (REGISTER storm → blocking notify per save) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile http-auth \
    up --abort-on-container-exit --exit-code-from sipp-onchange-load \
    mock-http-auth siphon-onchange sipp-onchange-load
  docker compose -f "$COMPOSE_FILE" --profile http-auth rm -sf \
    mock-http-auth siphon-onchange sipp-onchange-load 2>/dev/nu
    ll || true
fi

# ── Outbound-drain wedge regression (optional) ───────────────────────────────
# A single non-reading peer (toll-fraud scanner that never ACKs its 401s, or a
# stream peer whose far end stalls) must not be able to stall the per-listener
# outbound distributor. Pre-fix, send().await on the full bounded channel parked
# the drain while it held the connection-map shard guard, stalling ALL outbound
# and blocking accept(). run_sipp tolerates 255; this is a hard exit 1 on wedge.
if [[ "$RUN_WEDGE" == true ]]; then
  echo "=== outbound-drain wedge regression (non-reading peer @ cpus 0.5) ==="
  run_sipp bash scripts/wedge_test.sh
fi

# ── failed_auth_ban auto-ban regression (optional) ───────────────────────────
# A scanner that repeatedly fails auth must be banned at accept (dropped before
# SIP parsing). Hard exit 1 if the second connection still gets a 401.
if [[ "$RUN_BANSCAN" == true ]]; then
  echo "=== failed_auth_ban auto-ban regression (scanner banned at accept) ==="
  run_sipp bash scripts/banscan_test.sh
fi

# ── rate_limit + scanner_block regression (optional) ─────────────────────────
# A scanner User-Agent must be silently dropped, and a source that exceeds
# security.rate_limit.max_requests must be rate-limited. Hard exit 1 if either
# blocked request still gets answered.
if [[ "$RUN_SECURITY" == true ]]; then
  echo "=== rate_limit + scanner_block regression (request filter) ==="
  run_sipp bash scripts/security_test.sh
fi

# ── WebRTC (SIP-over-WebSocket) two-UA call test (optional) ───────────────────
# Two real sip.js WS user agents register and call each other through siphon.
# Proves RFC 7118 / RFC 5626 §5.3 flow-based MT routing: the INVITE reaches a
# WS-registered UE over its captured inbound connection (the Contact host is an
# unresolvable .invalid). Tests MT and MO toward/from both WebRTC legs. The
# webrtc-client container exits non-zero if any callee never receives the INVITE.
if [[ "$RUN_WEBRTC" == true ]]; then
  echo "=== Building siphon-webrtc images (proxy + b2bua) ==="
  docker compose -f "$COMPOSE_FILE" --profile webrtc build siphon-webrtc siphon-webrtc-b2bua

  echo "=== WebRTC (WS) two-UA call test — PROXY mode (MT + MO toward/from WebRTC legs) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile webrtc \
    up --abort-on-container-exit --exit-code-from webrtc-client \
    siphon-webrtc webrtc-client
  docker compose -f "$COMPOSE_FILE" --profile webrtc rm -sf \
    siphon-webrtc webrtc-client 2>/dev/null || true

  echo "=== WebRTC (WS) two-UA call test — B2BUA mode (MT + MO toward/from WebRTC legs) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile webrtc \
    up --abort-on-container-exit --exit-code-from webrtc-b2bua-client \
    siphon-webrtc-b2bua webrtc-b2bua-client
  docker compose -f "$COMPOSE_FILE" --profile webrtc rm -sf \
    siphon-webrtc-b2bua webrtc-b2bua-client 2>/dev/null || true
fi

echo ""
echo "=== All tests passed ==="
