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
#   ./scripts/run-tests.sh --control    # Also run the external control-plane (app rail) tests
#   ./scripts/run-tests.sh --b2bua     # Also run B2BUA call/session-timer/cancel/failure tests
set -euo pipefail

# SIPp exit code 255 means "dead call messages" (late retransmissions received
# after the scenario completed). This is not a real failure — tolerate it.
run_sipp() {
  local rc=0
  "$@" || rc=$?
  if [[ $rc -ne 0 ]]; then
    # 255 used to be exempted here. It is what SIPp returns when a scenario
    # times out — including when an assertion fails and the call never
    # completes — so exempting it made every scenario that hangs report green.
    echo "FAILED (exit $rc): $*"
    exit $rc
  fi
}

COMPOSE_FILE="sipp/docker-compose.yaml"
RUN_IPSEC=false
RUN_CHARGING=false
RUN_CALL=false
RUN_PRESENCE=false
RUN_RTPENGINE=false
RUN_RTPPROXY=false
RUN_VOICE_AI=false
RUN_CONTROL=false
RUN_REFER_SINGLE_LEG=false
RUN_REINVITE=false
RUN_REOFFER=false
RUN_B2BUA=false
RUN_B2BUA_AUTH=false
RUN_B2BUA_INVITE_AUTH=false
RUN_GATEWAY=false
RUN_AUTO100=false
RUN_HTTP_AUTH=false
RUN_WEDGE=false
RUN_BANSCAN=false
RUN_SECURITY=false
RUN_RFC4475=false
RUN_WEBRTC=false
SKIP_RUST=false

# Scenario modes selected on this invocation.  Exactly one is allowed — see the
# guard below.
SELECTED_MODES=()

for arg in "$@"; do
  case "$arg" in
    --ipsec)      RUN_IPSEC=true;      SELECTED_MODES+=("$arg") ;;
    --charging)   RUN_CHARGING=true;   SELECTED_MODES+=("$arg") ;;
    --call)       RUN_CALL=true;       SELECTED_MODES+=("$arg") ;;
    --presence)   RUN_PRESENCE=true;   SELECTED_MODES+=("$arg") ;;
    --rtpengine)  RUN_RTPENGINE=true;  SELECTED_MODES+=("$arg") ;;
    --rtpproxy)   RUN_RTPPROXY=true;   SELECTED_MODES+=("$arg") ;;
    --voice-ai)   RUN_VOICE_AI=true;   SELECTED_MODES+=("$arg") ;;
    --control)    RUN_CONTROL=true;    SELECTED_MODES+=("$arg") ;;
    --refer-single-leg) RUN_REFER_SINGLE_LEG=true; SELECTED_MODES+=("$arg") ;;
    --reinvite)   RUN_REINVITE=true;   SELECTED_MODES+=("$arg") ;;
    --reoffer)    RUN_REOFFER=true;    SELECTED_MODES+=("$arg") ;;
    --b2bua)      RUN_B2BUA=true;      SELECTED_MODES+=("$arg") ;;
    --b2bua-auth) RUN_B2BUA_AUTH=true; SELECTED_MODES+=("$arg") ;;
    --b2bua-invite-auth) RUN_B2BUA_INVITE_AUTH=true; SELECTED_MODES+=("$arg") ;;
    --gateway)    RUN_GATEWAY=true;    SELECTED_MODES+=("$arg") ;;
    --auto100)    RUN_AUTO100=true;    SELECTED_MODES+=("$arg") ;;
    --http-auth)  RUN_HTTP_AUTH=true;  SELECTED_MODES+=("$arg") ;;
    --wedge)      RUN_WEDGE=true;      SELECTED_MODES+=("$arg") ;;
    --banscan)    RUN_BANSCAN=true;    SELECTED_MODES+=("$arg") ;;
    --security)   RUN_SECURITY=true;   SELECTED_MODES+=("$arg") ;;
    --rfc4475)    RUN_RFC4475=true;    SELECTED_MODES+=("$arg") ;;
    --webrtc)     RUN_WEBRTC=true;     SELECTED_MODES+=("$arg") ;;
    --skip-rust)  SKIP_RUST=true ;;
    --help|-h)
      echo "Usage: $0 [<one scenario mode>] [--skip-rust]"
      echo
      echo "Scenario modes (pick at most ONE per run):"
      echo "  --ipsec --charging --call --presence --rtpengine --rtpproxy --reinvite"
      echo "  --voice-ai --refer-single-leg --reoffer --control"
      echo "  --b2bua --b2bua-auth --b2bua-invite-auth --gateway --auto100 --http-auth"
      echo "  --wedge --banscan"
      echo "  --security --rfc4475 --webrtc"
      echo
      echo "  --skip-rust   skip the Rust test step (combines with any mode)"
      echo
      echo "With no mode, only the Rust tests run."
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg"
      exit 1
      ;;
  esac
done

# ── One scenario mode per run ───────────────────────────────────────────────
# Each mode brings up its own long-lived service containers (siphon-*, and the
# rtpengine/rtpproxy mocks) on FIXED host ports, and those are only torn down by
# the EXIT trap at the end of the whole script — a mode's own teardown only
# `rm -sf`s its sipp peers.  So a second mode in the same invocation starts while
# the first mode's containers still hold the ports and docker fails the run with
# "failed to set up container networking: Address already in use", partway
# through, after the earlier mode already reported green.
#
# CI runs each mode as its own job for exactly this reason.  Fail fast with an
# explanation instead of letting the collision surface as a confusing mid-run
# docker error.
if (( ${#SELECTED_MODES[@]} > 1 )); then
  echo "error: pick ONE scenario mode per run (got: ${SELECTED_MODES[*]})" >&2
  echo >&2
  echo "Each mode binds fixed host ports and its service containers live until the" >&2
  echo "script exits, so a second mode collides with the first (docker: 'Address" >&2
  echo "already in use').  CI runs each mode as a separate job." >&2
  echo >&2
  echo "Run them in sequence instead:" >&2
  echo "    for mode in ${SELECTED_MODES[*]}; do $0 --skip-rust \"\$mode\" || break; done" >&2
  exit 2
fi

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

  echo "=== Proxy REFER passthrough test (in-dialog REFER loose-routed, no loop) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile proxy-refer up --abort-on-container-exit --exit-code-from sipp-proxy-refer-uac sipp-proxy-refer-uac sipp-proxy-refer-uas
  docker compose -f "$COMPOSE_FILE" --profile proxy-refer rm -sf sipp-proxy-refer-uac sipp-proxy-refer-uas sipp-proxy-refer-register 2>/dev/null || true
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

# ── Step 7a: Voice-AI B2BUA test (optional) ───────────────────────────────
if [[ "$RUN_VOICE_AI" == true ]]; then
  echo "=== SIPp voice-AI test (single-leg answer_local + WebSocket bridge) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile voice-ai up \
    --abort-on-container-exit --exit-code-from sipp-voice-ai-uac sipp-voice-ai-uac
  docker compose -f "$COMPOSE_FILE" --profile voice-ai rm -sf sipp-voice-ai-uac 2>/dev/null || true
fi

# ── Step 7a1: External control plane — the application rail (optional) ────
# Five cases against one siphon, both connection modes at once. Each SIPp
# scenario is the decider for its own step (--exit-code-from), and the parts the
# SIP wire cannot show — which connection was given the call, whether a media
# verb was performed or merely accepted, what `resync` handed back — are
# asserted on the mock application's and mock media engine's recorded frames.
if [[ "$RUN_CONTROL" == true ]]; then
  CONTROL_LOG_DIR="$(mktemp -d)"

  # NOTE on the greps below: the app and the engine both emit `json.dumps`
  # output, which writes `"key": "value"` WITH a space after the colon. A pattern
  # written without the space matches nothing and the assertion passes
  # vacuously — which is the whole failure mode these asserts exist to avoid.
  control_dump_logs() {
    docker compose -f "$COMPOSE_FILE" logs control-app-edge > "$CONTROL_LOG_DIR/control-app-edge.log" 2>&1 || true
    docker compose -f "$COMPOSE_FILE" logs control-app-ivr > "$CONTROL_LOG_DIR/control-app-ivr.log" 2>&1 || true
    docker compose -f "$COMPOSE_FILE" logs mock-control-rtp > "$CONTROL_LOG_DIR/mock-control-rtp.log" 2>&1 || true
    docker compose -f "$COMPOSE_FILE" logs siphon-control > "$CONTROL_LOG_DIR/siphon-control.log" 2>&1 || true
  }

  # A case that never ran prints no verdict at all, and that is a failure too —
  # it is what catches an application that was never reached.
  assert_control_verdict() {
    local case="$1" log="$CONTROL_LOG_DIR/$2" line
    line="$(grep 'CONTROL-VERDICT' "$log" 2>/dev/null | grep "\"case\": \"$case\"" || true)"
    if [[ -z "$line" ]]; then
      echo "FAILED: no CONTROL-VERDICT for case '$case' in $log — the control app never completed it"
      exit 1
    fi
    if grep -q '"pass": false' <<<"$line"; then
      echo "FAILED: control-plane case '$case':"
      echo "$line"
      exit 1
    fi
    echo "  ✓ control case '$case': $line"
  }

  # The difference between a media verb siphon *accepted* and one it *performed*
  # is invisible to SIPp; the engine's own record is the only witness.
  assert_engine_performed() {
    local verb="$1" log="$CONTROL_LOG_DIR/mock-control-rtp.log"
    if ! grep -q "\"command\": \"$verb\"" "$log"; then
      echo "FAILED: the media engine never received '$verb' — the verb was accepted but never performed"
      exit 1
    fi
    echo "  ✓ media engine performed '$verb'"
  }

  echo "=== SIPp control-plane tests (external application rail) ==="
  # --force-recreate: the persistent app dials siphon once at start-up and holds
  # its sockets for life, so a re-run that recreates siphon (a rebuilt image)
  # while reusing a running app leaves that app connected to nothing. Recreating
  # the set together keeps the stack coherent. The app's healthcheck catches the
  # case too — it heartbeats only while it can actually take a call — but a
  # loud "unhealthy" is still a re-run someone has to debug.
  docker compose -f "$COMPOSE_FILE" --profile control up -d --force-recreate --wait \
    mock-control-rtp control-app-edge siphon-control control-app-ivr

  echo "--- deferred handover: siphon parks the INVITE, the app answers it ---"
  run_sipp docker compose -f "$COMPOSE_FILE" --profile control up \
    --abort-on-container-exit --exit-code-from sipp-control-handover-uac sipp-control-handover-uac
  docker compose -f "$COMPOSE_FILE" --profile control rm -sf sipp-control-handover-uac 2>/dev/null || true
  control_dump_logs
  assert_control_verdict handover control-app-edge.log

  echo "--- handoff deadline: the controller never acts, siphon applies its default ---"
  run_sipp docker compose -f "$COMPOSE_FILE" --profile control up \
    --abort-on-container-exit --exit-code-from sipp-control-deadline-uac sipp-control-deadline-uac
  docker compose -f "$COMPOSE_FILE" --profile control rm -sf sipp-control-deadline-uac 2>/dev/null || true
  control_dump_logs
  assert_control_verdict deadline control-app-ivr.log

  echo "--- media verbs on an answer-first channel (accepted AND performed) ---"
  run_sipp docker compose -f "$COMPOSE_FILE" --profile control up \
    --abort-on-container-exit --exit-code-from sipp-control-media-uac sipp-control-media-uac
  docker compose -f "$COMPOSE_FILE" --profile control rm -sf sipp-control-media-uac 2>/dev/null || true
  control_dump_logs
  assert_control_verdict media control-app-edge.log
  assert_engine_performed play_media
  assert_engine_performed stop_media

  echo "--- exactly-one-owner dispatch across several app connections ---"
  run_sipp docker compose -f "$COMPOSE_FILE" --profile control up \
    --abort-on-container-exit --exit-code-from sipp-control-owner-uac sipp-control-owner-uac
  docker compose -f "$COMPOSE_FILE" --profile control rm -sf sipp-control-owner-uac 2>/dev/null || true
  control_dump_logs
  assert_control_verdict owner control-app-ivr.log

  # Last of the persistent-app cases on purpose: it drops one of the app's
  # sockets, so anything queued behind it would be running with fewer.
  echo "--- resync: the owner drops, reconnects in the grace window, re-claims ---"
  run_sipp docker compose -f "$COMPOSE_FILE" --profile control up \
    --abort-on-container-exit --exit-code-from sipp-control-resync-uac sipp-control-resync-uac
  docker compose -f "$COMPOSE_FILE" --profile control rm -sf sipp-control-resync-uac 2>/dev/null || true
  control_dump_logs
  assert_control_verdict resync control-app-ivr.log

  echo "Control-plane logs: $CONTROL_LOG_DIR"
fi

# ── Step 7a2: Single-leg cold transfer (optional) ─────────────────────────
if [[ "$RUN_REFER_SINGLE_LEG" == true ]]; then
  echo "=== SIPp cold-transfer test (single-leg answer -> in-dialog REFER) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile refer-single-leg up \
    --abort-on-container-exit --exit-code-from sipp-refer-single-leg-uac sipp-refer-single-leg-uac
  docker compose -f "$COMPOSE_FILE" --profile refer-single-leg rm -sf sipp-refer-single-leg-uac 2>/dev/null || true

  echo "=== SIPp challenged-REFER test (407 -> credentialed retry) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile refer-single-leg up \
    --abort-on-container-exit --exit-code-from sipp-refer-challenge-uac sipp-refer-challenge-uac
  docker compose -f "$COMPOSE_FILE" --profile refer-single-leg rm -sf sipp-refer-challenge-uac 2>/dev/null || true
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
  # --exit-code-from is load-bearing: without it the step passed on the compose
  # exit status regardless of sipp's, and the mode was green while the resume
  # re-INVITE never completed.
  run_sipp docker compose -f "$COMPOSE_FILE" --profile reinvite --profile rtpengine up --abort-on-container-exit --exit-code-from sipp-reinvite-uac sipp-reinvite-uac sipp-reinvite-uas
  docker compose -f "$COMPOSE_FILE" --profile reinvite --profile rtpengine rm -sf sipp-reinvite-uac sipp-reinvite-uas 2>/dev/null || true
fi

# ── Step 8b: Re-INVITE renegotiation on the siphon-rtp backend (optional) ──
if [[ "$RUN_REOFFER" == true ]]; then
  echo "=== SIPp re-offer test (hold/resume renegotiates in place on siphon-rtp) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile reoffer run --rm sipp-reoffer-register
  run_sipp docker compose -f "$COMPOSE_FILE" --profile reoffer up \
    --abort-on-container-exit --exit-code-from sipp-reoffer-uac sipp-reoffer-uac sipp-reoffer-uas

  # The SIPp side alone cannot tell a renegotiation from a replacement — both
  # answer the re-INVITE with a 200. What separates them is the verb siphon put
  # on the control channel, so assert on what the engine actually received.
  echo "--- asserting the control verbs the engine saw ---"
  verbs="$(docker compose -f "$COMPOSE_FILE" --profile reoffer logs --no-log-prefix mock-siphon-rtp-reoffer 2>/dev/null \
    | grep -oE '"command": ?"[a-z_]+"' | sed -E 's/"command": ?"//; s/"//' | grep -E '^(offer|reoffer)$' || true)"
  offers="$(printf '%s\n' "$verbs" | grep -c '^offer$' || true)"
  reoffers="$(printf '%s\n' "$verbs" | grep -c '^reoffer$' || true)"
  echo "control verbs: offer=$offers reoffer=$reoffers"

  if [[ "$offers" -ne 1 ]]; then
    echo "FAIL: expected exactly 1 offer (the initial INVITE), got $offers." >&2
    echo "      A second offer means a re-INVITE replaced the media session:" >&2
    echo "      fresh ports, and any WebSocket bridge, tee or SIPREC fork gone." >&2
    docker compose -f "$COMPOSE_FILE" --profile reoffer logs --no-log-prefix mock-siphon-rtp-reoffer >&2 || true
    exit 1
  fi
  if [[ "$reoffers" -lt 2 ]]; then
    echo "FAIL: expected at least 2 reoffers (hold + resume), got $reoffers." >&2
    docker compose -f "$COMPOSE_FILE" --profile reoffer logs --no-log-prefix mock-siphon-rtp-reoffer >&2 || true
    exit 1
  fi
  echo "OK: the re-INVITEs renegotiated in place; the media session was never replaced."

  docker compose -f "$COMPOSE_FILE" --profile reoffer rm -sf sipp-reoffer-uac sipp-reoffer-uas 2>/dev/null || true
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

  echo "=== B2BUA BYE-glare test (in-dialog BYE after teardown → 481, not a silent drop) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-bye-glare up --abort-on-container-exit --exit-code-from sipp-b2bua-bye-glare-uac sipp-b2bua-bye-glare-uac sipp-b2bua-bye-glare-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-bye-glare rm -sf sipp-b2bua-bye-glare-uac sipp-b2bua-bye-glare-uas 2>/dev/null || true

  echo "=== B2BUA REFER test (RFC 3515 transparent blind transfer) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-refer up --abort-on-container-exit --exit-code-from sipp-b2bua-refer-uac sipp-b2bua-refer-uac sipp-b2bua-refer-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-refer rm -sf sipp-b2bua-refer-uac sipp-b2bua-refer-uas 2>/dev/null || true

  echo "=== B2BUA REFER reject test (loop-safe 603 default, no egress) ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-refer-reject up -d --wait siphon-b2bua-refer-modes
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-refer-reject up --abort-on-container-exit --exit-code-from sipp-b2bua-refer-reject-uac sipp-b2bua-refer-reject-uac sipp-b2bua-refer-reject-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua-refer-reject rm -sf sipp-b2bua-refer-reject-uac sipp-b2bua-refer-reject-uas 2>/dev/null || true

  echo "=== B2BUA REFER siphon-terminated test (dial target + promote + BYE) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-refer-terminate up --abort-on-container-exit --exit-code-from sipp-b2bua-refer-terminate-uac sipp-b2bua-refer-terminate-uac sipp-b2bua-refer-terminate-bob-uas sipp-b2bua-refer-terminate-carol-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua-refer-terminate down 2>/dev/null || true

  echo "=== B2BUA REFER terminate + REAL rtpengine (media re-anchor: offer/answer/delete) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-rtpengine-refer up --abort-on-container-exit --exit-code-from sipp-anchored-refer-uac sipp-anchored-refer-uac sipp-anchored-refer-bob-uas sipp-anchored-refer-carol-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua-rtpengine-refer down 2>/dev/null || true

  echo "=== B2BUA CANCEL test (INVITE → CANCEL → 487) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-cancel up --abort-on-container-exit --exit-code-from sipp-b2bua-cancel-uac sipp-b2bua-cancel-uac sipp-b2bua-cancel-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-cancel rm -sf sipp-b2bua-cancel-uac sipp-b2bua-cancel-uas 2>/dev/null || true

  echo "=== B2BUA CANCEL 487-ACK test (the CANCELled B-leg's 487 is ACKed — RFC 3261 §17.1.1.3) ==="
  # --exit-code-from names the UAS, not the UAC: the A-leg gets a correct 487
  # whether or not siphon ever ACKs the B-leg's, so reading the UAC's exit code
  # would pass vacuously.  The UAS is the only side that can see the missing ACK.
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-cancel-ack up --abort-on-container-exit --exit-code-from sipp-b2bua-cancel-ack-uas sipp-b2bua-cancel-ack-uac sipp-b2bua-cancel-ack-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-cancel-ack rm -sf sipp-b2bua-cancel-ack-uac sipp-b2bua-cancel-ack-uas 2>/dev/null || true

  echo "=== B2BUA failure test (INVITE → 486 Busy) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-failure run --rm sipp-b2bua-register-failure
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-failure up --abort-on-container-exit --exit-code-from sipp-b2bua-failure-uac sipp-b2bua-failure-uac sipp-b2bua-failure-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-failure rm -sf sipp-b2bua-failure-uac sipp-b2bua-failure-uas 2>/dev/null || true

  echo "=== B2BUA topology hiding test (CSeq/Max-Forwards/From host/SDP/PAI) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-topology up --abort-on-container-exit --exit-code-from sipp-b2bua-topology-uac sipp-b2bua-topology-uac sipp-b2bua-topology-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua --profile b2bua-topology rm -sf sipp-b2bua-topology-uac sipp-b2bua-topology-uas 2>/dev/null || true
fi

# ── Step 9b: B2BUA device-driven proxy-auth test (optional) ─────────────────
# A B-leg 407 relayed to the caller (auth_passthrough) must NOT draw a spurious
# 502 in response to the caller's ACK for that 407. The UAC scenario aborts on
# an unexpected 502, so --exit-code-from makes it a hard FAIL on the buggy build.
if [[ "$RUN_B2BUA_AUTH" == true ]]; then
  echo "=== Building siphon-b2bua-auth image ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-auth build siphon-b2bua-auth

  echo "=== Starting siphon-b2bua-auth ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-auth up -d --wait siphon-b2bua-auth

  echo "=== B2BUA auth-passthrough test (outbound call to a PBX that 407s; challenge relayed, no spurious 502) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-auth up --abort-on-container-exit --exit-code-from sipp-b2bua-auth-uac sipp-b2bua-auth-uac sipp-b2bua-auth-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua-auth rm -sf sipp-b2bua-auth-uac sipp-b2bua-auth-uas 2>/dev/null || true
fi

# ── Step 9c: B2BUA A-leg INVITE authentication test (optional) ──────────────
# The mirror of 9b: siphon challenges the CALLER from @b2bua.on_invite. With a
# @b2bua handler registered the INVITE never reaches @proxy.on_request, so the
# challenge runs against the Call object. The UAC asserts the 407 + its
# Proxy-Authenticate challenge and its UAS To-tag; the UAS asserts it sees
# exactly one B-leg INVITE (a build that cannot challenge dials the
# unauthenticated one through) carrying no leaked Proxy-Authorization.
if [[ "$RUN_B2BUA_INVITE_AUTH" == true ]]; then
  echo "=== Building siphon-b2bua-invite-auth image ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-invite-auth build siphon-b2bua-invite-auth

  echo "=== Starting siphon-b2bua-invite-auth ==="
  docker compose -f "$COMPOSE_FILE" --profile b2bua-invite-auth up -d --wait siphon-b2bua-invite-auth

  echo "=== B2BUA A-leg INVITE auth test (siphon 407s the caller, then bridges the authenticated re-INVITE) ==="
  run_sipp docker compose -f "$COMPOSE_FILE" --profile b2bua-invite-auth up --abort-on-container-exit --exit-code-from sipp-b2bua-invite-auth-uac sipp-b2bua-invite-auth-uac sipp-b2bua-invite-auth-uas
  docker compose -f "$COMPOSE_FILE" --profile b2bua-invite-auth rm -sf sipp-b2bua-invite-auth-uac sipp-b2bua-invite-auth-uas 2>/dev/null || true
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

# ── Step 11b: Charging against a real CGRateS OCS/CDF (optional) ──────────────
# Rf + Ro end-to-end: proves the CER Acct-Application-Id fix (a strict
# go-diameter peer rejects otherwise), a completed-call CDR, and Ro credit
# reservation + 4012-driven disconnect. Self-contained (CGRateS internal DBs).
if [[ "$RUN_CHARGING" == true ]]; then
  echo "=== Rf + Ro charging against CGRateS ==="
  ./scripts/charging_test.sh
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

# ── RFC 4475 on-the-wire regression (optional) ───────────────────────────────
# The byte-exact torture messages go out on a real UDP socket. Each must be
# accepted (200 from the script), refused with the status RFC 4475 names (400,
# or 505 for a bad version), or dropped with no response where the parser cannot
# represent the message at all. The Rust corpus test proves the decision; this
# proves the peer actually receives it.
if [[ "$RUN_RFC4475" == true ]]; then
  echo "=== RFC 4475 torture corpus regression (on the wire) ==="
  run_sipp bash scripts/rfc4475_test.sh
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
