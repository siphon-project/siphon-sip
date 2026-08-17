#!/usr/bin/env bash
# Routing a B2BUA B-leg through the binding's RFC 3327 Path — SIPp acceptance
# test.
#
# The B2BUA builds a FRESH B-leg INVITE instead of forwarding the caller's, so
# none of the proxy-side Path handling applies to it.  Four scenarios on one
# fixture (scripts/b2bua_path.py), each registering a binding whose Contact is
# somewhere the call cannot be completed and whose Path points at a live edge:
#
#   1. Parallel call.fork() over ONE binding.  The plainest form of the bug — a
#      callee registered through an edge proxy was unreachable in B2BUA mode even
#      with a single binding, because the B-leg went to its Contact.
#
#   2. Sequential call.fork() over TWO bindings with different Path tokens.  The
#      first edge answers 503, so the second branch has to be routed by the
#      SECOND binding's own Path; a shared route set delivers it back to the dead
#      edge and the caller gets the 503.  (503 rather than the proxy fixture's
#      404: the B2BUA's sequential strategy advances through the LCR
#      route-sequence engine, where a 404 is deliberately not a reroute cause.)
#
#   3. call.dial(uri, route=contact.path).  `route=` already existed but only set
#      the header, so the INVITE was correctly formed and sent to the wrong place.
#
#   4. Over-MTU INVITE, Contact host a resolvable DNS name with a live TCP
#      listener (the decoy).  The RFC 3261 §18.1.1 UDP→TCP re-probe has to follow
#      the same URI the destination came from; probing the Contact resolves the
#      decoy and lands the B-leg there, bypassing the Path on exactly the
#      messages most likely to need it (an INVITE with SDP).
#
# Every caller demands a 200 — anything else fails the run — and each scenario
# additionally asserts on the edges' logs, so a call that siphon answered itself
# or that reached only one of two edges cannot pass.
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE=(docker compose -f sipp/docker-compose.yaml --profile b2bua-path)

cleanup() { "${COMPOSE[@]}" down --remove-orphans -t 3 >/dev/null 2>&1 || true; }
trap cleanup EXIT

fail() {
  echo "FAILED: $1"
  echo "--- siphon-b2bua-path logs ---"
  "${COMPOSE[@]}" logs siphon-b2bua-path 2>/dev/null | tail -100 || true
  exit 1
}

# An edge received an INVITE at all.  SIPp's own counter line is the signal, the
# same check the failover acceptance test uses.
edge_received_invite() {
  "${COMPOSE[@]}" logs "$1" 2>/dev/null | grep -a "> INVITE" | grep -qE "INVITE +[1-9]"
}

echo "=== B2BUA: routing a binding through its RFC 3327 Path ==="
echo "[*] Building siphon image..."
"${COMPOSE[@]}" build siphon-b2bua-path

echo "[*] Starting siphon..."
"${COMPOSE[@]}" up -d --wait siphon-b2bua-path || fail "siphon did not become healthy"

# ── 1: parallel fork, one binding ───────────────────────────────────────────
echo
echo "--- 1/4: parallel call.fork(), one binding (RFC 3327 §5.3) ---"

echo "[*] Registering bob (Contact 172.20.0.200 = nowhere, Path -> edge .84)..."
"${COMPOSE[@]}" run --rm sipp-b2bua-path-register-bob >/dev/null \
  || fail "bob did not register"

echo "[*] Starting bob's edge (.84 answers 200)..."
"${COMPOSE[@]}" up -d sipp-b2bua-path-edge-answer
sleep 2

echo "[*] Calling bob..."
rc=0
"${COMPOSE[@]}" run --rm sipp-b2bua-path-uac || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- edge (.84) logs ---"
  "${COMPOSE[@]}" logs sipp-b2bua-path-edge-answer 2>/dev/null | tail -30 || true
  fail "the call was not answered (exit ${rc}) — the B-leg did not follow the binding's Path"
fi
edge_received_invite sipp-b2bua-path-edge-answer \
  || fail "the edge never received the INVITE — the B-leg was sent to the Contact URI"

"${COMPOSE[@]}" rm -sf sipp-b2bua-path-edge-answer >/dev/null 2>&1 || true
echo "PASS: a single binding's B-leg was routed through its Path"

# ── 2: sequential fork, two bindings ────────────────────────────────────────
echo
echo "--- 2/4: sequential call.fork(), per-branch route sets ---"

echo "[*] Registering bobseq's two bindings (token-seq-a q=1.0, token-seq-b q=0.5)..."
"${COMPOSE[@]}" run --rm sipp-b2bua-path-register-seq-a >/dev/null \
  || fail "bobseq binding A did not register"
"${COMPOSE[@]}" run --rm sipp-b2bua-path-register-seq-b >/dev/null \
  || fail "bobseq binding B did not register"

echo "[*] Starting both edges (.85 answers 503, .86 answers 200)..."
"${COMPOSE[@]}" up -d sipp-b2bua-path-edge-reject sipp-b2bua-path-edge-answer-b
sleep 2

echo "[*] Calling bobseq..."
rc=0
"${COMPOSE[@]}" run --rm sipp-b2bua-path-uac-seq || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- dead edge (.85) logs ---"
  "${COMPOSE[@]}" logs sipp-b2bua-path-edge-reject 2>/dev/null | tail -30 || true
  echo "--- live edge (.86) logs ---"
  "${COMPOSE[@]}" logs sipp-b2bua-path-edge-answer-b 2>/dev/null | tail -30 || true
  fail "the call was not answered (exit ${rc}) — the failover branch did not reach binding B's edge"
fi
edge_received_invite sipp-b2bua-path-edge-reject \
  || fail "binding A's edge never received the INVITE — branch 0 was not routed by its Path"
edge_received_invite sipp-b2bua-path-edge-answer-b \
  || fail "binding B's edge never received the INVITE — the failover branch reused binding A's route set"

"${COMPOSE[@]}" rm -sf sipp-b2bua-path-edge-reject sipp-b2bua-path-edge-answer-b >/dev/null 2>&1 || true
echo "PASS: each sequential branch was routed through its own binding's Path"

# ── 3: call.dial(route=…) ───────────────────────────────────────────────────
echo
echo "--- 3/4: call.dial(uri, route=contact.path) is routable, not decorative ---"

echo "[*] Registering bobdial (Path -> edge .84)..."
"${COMPOSE[@]}" run --rm sipp-b2bua-path-register-dial >/dev/null \
  || fail "bobdial did not register"

echo "[*] Starting the edge (.84 answers 200)..."
"${COMPOSE[@]}" up -d sipp-b2bua-path-edge-answer
sleep 2

echo "[*] Calling bobdial..."
rc=0
"${COMPOSE[@]}" run --rm sipp-b2bua-path-uac-dial || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- edge (.84) logs ---"
  "${COMPOSE[@]}" logs sipp-b2bua-path-edge-answer 2>/dev/null | tail -30 || true
  fail "the call was not answered (exit ${rc}) — dial's route= set the header but not the destination"
fi
edge_received_invite sipp-b2bua-path-edge-answer \
  || fail "the edge never received the INVITE — dial ignored its route set when picking a destination"

"${COMPOSE[@]}" rm -sf sipp-b2bua-path-edge-answer >/dev/null 2>&1 || true
echo "PASS: dial's route set decided the destination"

# ── 4: over-MTU B-leg ───────────────────────────────────────────────────────
echo
echo "--- 4/4: over-MTU B-leg re-probes the route set, not the Contact (§18.1.1) ---"

echo "[*] Starting the decoy (TCP listener at bobmtu's Contact host)..."
"${COMPOSE[@]}" up -d sipp-b2bua-path-decoy
sleep 2

echo "[*] Registering bobmtu (Contact -> decoy's DNS name, Path -> UDP edge .84)..."
"${COMPOSE[@]}" run --rm sipp-b2bua-path-register-mtu >/dev/null \
  || fail "bobmtu did not register"

echo "[*] Starting the edge (.84, UDP only)..."
"${COMPOSE[@]}" up -d sipp-b2bua-path-edge-answer
sleep 2

echo "[*] Calling bobmtu with an over-MTU INVITE..."
rc=0
"${COMPOSE[@]}" run --rm sipp-b2bua-path-uac-mtu || rc=$?
if [[ ${rc} -ne 0 ]]; then
  echo "--- edge (.84) logs ---"
  "${COMPOSE[@]}" logs sipp-b2bua-path-edge-answer 2>/dev/null | tail -30 || true
  echo "--- decoy logs ---"
  "${COMPOSE[@]}" logs sipp-b2bua-path-decoy 2>/dev/null | tail -30 || true
  fail "the call was not answered (exit ${rc}) — the over-MTU B-leg left the route set"
fi
edge_received_invite sipp-b2bua-path-edge-answer \
  || fail "the edge never received the over-MTU INVITE"
if edge_received_invite sipp-b2bua-path-decoy; then
  fail "the decoy received the INVITE — the §18.1.1 re-probe resolved the Contact host and moved the B-leg there"
fi

echo "PASS: the over-MTU re-probe followed the route set and the decoy was never contacted"
echo
echo "ALL PASS"
